//! Что руки умеют делать с машиной. Здесь нет ни сети, ни кадров — только
//! файловая система и процессы, поэтому всё это одинаково работает и в
//! демоне на той стороне ssh, и прямо в процессе клиента, когда машина
//! своя.

use std::{
    io,
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, UNIX_EPOCH},
};

use tokio::{
    fs,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    process::Command,
};

use crate::{
    limits::Limits,
    proto::{Answer, Code, Entry, Failure, Kind, Op, Request},
};

/// Окно потокового поиска: файл идёт мимо кусками такого размера.
const CHUNK: usize = 1024 * 1024;

/// Хвост имени временного файла — чтобы две записи подряд не столкнулись.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Руки: потолки машины и операции над ней.
pub struct Ops {
    pub limits: Limits,
}

impl Ops {
    pub fn new(limits: Limits) -> Self {
        Self { limits }
    }

    /// Исполнить запрос. Возвращает ответ и его тело (байты файла или
    /// пустоту).
    pub async fn run(&self, request: Request, body: Vec<u8>) -> Result<(Answer, Vec<u8>), Failure> {
        let cwd = request.cwd.as_deref();
        match request.op {
            Op::Ping => Ok((Answer::Pong, Vec::new())),

            Op::Stat { path } => {
                let at = self.resolve(cwd, &path)?;
                Ok((Answer::Stat { entry: entry_at(&at).await? }, Vec::new()))
            }

            Op::List { path } => {
                let at = self.resolve(cwd, &path)?;
                let (entries, stopped) = self.list(&at).await?;
                Ok((Answer::List { entries, stopped }, Vec::new()))
            }

            Op::Read { path, offset, len } => {
                let at = self.resolve(cwd, &path)?;
                let (total, bytes) = self.read(&at, offset, len).await?;
                Ok((Answer::Read { total, offset }, bytes))
            }

            Op::Write { path, create_dirs, mode } => {
                let at = self.resolve(cwd, &path)?;
                let total = self.write(&at, &body, create_dirs, mode).await?;
                Ok((Answer::Wrote { total }, Vec::new()))
            }

            Op::WriteAt { path, offset, truncate } => {
                let at = self.resolve(cwd, &path)?;
                let total = self.write_at(&at, offset, &body, truncate).await?;
                Ok((Answer::Wrote { total }, Vec::new()))
            }

            Op::Find { path, from, limit } => {
                let at = self.resolve(cwd, &path)?;
                let (total, offsets, stopped) = self.find(&at, &body, from, limit, CHUNK).await?;
                Ok((Answer::Find { total, offsets, stopped }, Vec::new()))
            }

            Op::Mkdir { path, parents } => {
                let at = self.resolve(cwd, &path)?;
                let made =
                    if parents { fs::create_dir_all(&at).await } else { fs::create_dir(&at).await };
                made.map_err(|error| io_fail(&at, &error))?;
                Ok((Answer::Done, Vec::new()))
            }

            Op::Remove { path, recursive } => {
                let at = self.resolve(cwd, &path)?;
                self.remove(&at, recursive).await?;
                Ok((Answer::Done, Vec::new()))
            }

            Op::Rename { from, to } => {
                let source = self.resolve(cwd, &from)?;
                let target = self.resolve(cwd, &to)?;
                fs::rename(&source, &target)
                    .await
                    .map_err(|error| io_fail(&source, &error))?;
                Ok((Answer::Done, Vec::new()))
            }

            Op::Exec { command, timeout_ms } => self.exec(cwd, &command, timeout_ms, body).await,
        }
    }

    /// Путь так, как его видит машина: `~` разворачивается, относительный
    /// считается от `cwd`, `..` разбирается, и результат обязан лежать в
    /// разрешённых корнях.
    ///
    /// `~` разворачиваем сами: путь, ушедший в шелл в кавычках, оставался
    /// тильдой как есть — и файл не находился по вине кавычек.
    pub fn resolve(&self, cwd: Option<&str>, path: &str) -> Result<PathBuf, Failure> {
        if path.trim().is_empty() {
            return Err(Failure::invalid("path is empty"));
        }
        let wanted = expand_home(path);
        let full = if wanted.is_absolute() {
            wanted
        } else {
            let base = match cwd {
                Some(dir) => expand_home(dir),
                // без рабочего каталога — от каталога процесса, как это
                // сделал бы и шелл в ssh-сессии
                None => std::env::current_dir()
                    .map_err(|error| Failure::new(Code::Io, error.to_string()))?,
            };
            base.join(wanted)
        };
        let normalized = normalize(&full);
        if !self.limits.allows(&normalized) {
            return Err(Failure::new(
                Code::Denied,
                format!("{}: outside the directories this machine hands out", normalized.display()),
            ));
        }
        Ok(normalized)
    }

    async fn list(&self, path: &Path) -> Result<(Vec<Entry>, bool), Failure> {
        let mut dir = fs::read_dir(path).await.map_err(|error| io_fail(path, &error))?;
        let mut entries = Vec::new();
        let mut stopped = false;
        while let Some(found) = dir.next_entry().await.map_err(|error| io_fail(path, &error))? {
            if entries.len() as u64 >= self.limits.max_hits {
                stopped = true;
                break;
            }
            entries.push(entry_at(&found.path()).await?);
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok((entries, stopped))
    }

    /// Кусок файла и его полная длина. Смещение за концом — пустой кусок, а
    /// не ошибка: спрашивающий видит `total` и сам решает, что это значит.
    async fn read(
        &self,
        path: &Path,
        offset: u64,
        len: Option<u64>,
    ) -> Result<(u64, Vec<u8>), Failure> {
        let meta = fs::metadata(path).await.map_err(|error| io_fail(path, &error))?;
        if meta.is_dir() {
            return Err(Failure::new(
                Code::NotAFile,
                format!("{}: is a directory, not a file", path.display()),
            ));
        }
        let total = meta.len();
        let start = offset.min(total);
        let want = len.unwrap_or(total - start).min(total - start);
        if want > self.limits.max_read {
            return Err(Failure::new(
                Code::TooLarge,
                format!(
                    "{}: asked for {want} bytes, this machine hands out at most {} per read — \
                     read it in windows",
                    path.display(),
                    self.limits.max_read
                ),
            ));
        }
        let mut file = fs::File::open(path).await.map_err(|error| io_fail(path, &error))?;
        file.seek(io::SeekFrom::Start(start))
            .await
            .map_err(|error| io_fail(path, &error))?;
        let mut bytes = Vec::with_capacity(want as usize);
        file.take(want)
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| io_fail(path, &error))?;
        Ok((total, bytes))
    }

    /// Файл целиком. Пишется через соседний временный файл и `rename`:
    /// оборванная на середине запись иначе оставила бы обрубок вместо
    /// прежнего содержимого.
    async fn write(
        &self,
        path: &Path,
        data: &[u8],
        create_dirs: bool,
        mode: Option<u32>,
    ) -> Result<u64, Failure> {
        self.check_size(path, data.len() as u64)?;
        let parent = path
            .parent()
            .ok_or_else(|| Failure::invalid(format!("{}: has no parent directory", path.display())))?;
        if create_dirs {
            fs::create_dir_all(parent)
                .await
                .map_err(|error| io_fail(parent, &error))?;
        }
        // права переживают замену: временный файл рождается с umask демона
        let existing = fs::metadata(path).await.ok().map(|meta| meta.permissions().mode());
        let temp = parent.join(format!(
            ".eva-hands.{}.{}.tmp",
            std::process::id(),
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let written = write_temp(&temp, data, mode.or(existing)).await;
        let renamed = match written {
            Ok(()) => fs::rename(&temp, path).await.map_err(|error| io_fail(path, &error)),
            Err(failure) => Err(failure),
        };
        if renamed.is_err() {
            let _ = fs::remove_file(&temp).await;
        }
        renamed?;
        Ok(data.len() as u64)
    }

    /// Байты по смещению поверх существующих. В отличие от записи целиком
    /// атомарной быть не может: это правка на месте.
    async fn write_at(
        &self,
        path: &Path,
        offset: u64,
        data: &[u8],
        truncate: bool,
    ) -> Result<u64, Failure> {
        self.check_size(path, data.len() as u64)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .await
            .map_err(|error| io_fail(path, &error))?;
        file.seek(io::SeekFrom::Start(offset))
            .await
            .map_err(|error| io_fail(path, &error))?;
        file.write_all(data).await.map_err(|error| io_fail(path, &error))?;
        if truncate {
            file.set_len(offset + data.len() as u64)
                .await
                .map_err(|error| io_fail(path, &error))?;
        }
        file.flush().await.map_err(|error| io_fail(path, &error))?;
        let meta = file.metadata().await.map_err(|error| io_fail(path, &error))?;
        Ok(meta.len())
    }

    /// Смещения вхождений образца и полная длина файла.
    ///
    /// Файл течёт мимо окном, а не ложится в память: игровые архивы бывают
    /// на гигабайты. Окно перекрывается на длину образца без единицы —
    /// иначе вхождение, попавшее на стык, потерялось бы. Набрав `limit`,
    /// обрываем чтение на месте: искомое обычно лежит в начале.
    async fn find(
        &self,
        path: &Path,
        pattern: &[u8],
        from: u64,
        limit: u64,
        chunk: usize,
    ) -> Result<(u64, Vec<u64>, bool), Failure> {
        if pattern.is_empty() {
            return Err(Failure::invalid("nothing to search for"));
        }
        if limit == 0 {
            return Err(Failure::invalid("limit must be at least one hit"));
        }
        let limit = limit.min(self.limits.max_hits);
        let meta = fs::metadata(path).await.map_err(|error| io_fail(path, &error))?;
        if meta.is_dir() {
            return Err(Failure::new(
                Code::NotAFile,
                format!("{}: is a directory, not a file", path.display()),
            ));
        }
        let total = meta.len();
        let mut file = fs::File::open(path).await.map_err(|error| io_fail(path, &error))?;
        file.seek(io::SeekFrom::Start(from.min(total)))
            .await
            .map_err(|error| io_fail(path, &error))?;

        let finder = memchr::memmem::Finder::new(pattern);
        let overlap = pattern.len() - 1;
        let mut window = vec![0u8; chunk + overlap];
        // сколько байт файла уже прошло ЛЕВЕЕ начала окна
        let mut consumed = from.min(total);
        let mut kept = 0usize;
        let mut offsets = Vec::new();
        let mut stopped = false;
        loop {
            let read = file
                .read(&mut window[kept..])
                .await
                .map_err(|error| io_fail(path, &error))?;
            if read == 0 {
                break;
            }
            let filled = kept + read;
            for at in finder.find_iter(&window[..filled]) {
                offsets.push(consumed + at as u64);
                if offsets.len() as u64 >= limit {
                    stopped = true;
                    break;
                }
            }
            if stopped {
                break;
            }
            // хвост длиной в перекрытие переезжает в начало окна
            kept = overlap.min(filled);
            let tail = filled - kept;
            window.copy_within(tail..filled, 0);
            consumed += tail as u64;
        }
        Ok((total, offsets, stopped))
    }

    async fn remove(&self, path: &Path, recursive: bool) -> Result<(), Failure> {
        let meta = fs::symlink_metadata(path)
            .await
            .map_err(|error| io_fail(path, &error))?;
        let removed = if meta.is_dir() {
            if recursive { fs::remove_dir_all(path).await } else { fs::remove_dir(path).await }
        } else {
            fs::remove_file(path).await
        };
        removed.map_err(|error| io_fail(path, &error))
    }

    /// Команда через `sh -c`. Окружение неинтерактивное: терминала здесь
    /// нет, и программа, решившая, что он есть, висит до самого таймаута.
    async fn exec(
        &self,
        cwd: Option<&str>,
        command: &str,
        timeout_ms: u64,
        stdin: Vec<u8>,
    ) -> Result<(Answer, Vec<u8>), Failure> {
        if !self.limits.exec {
            return Err(Failure::new(
                Code::Unsupported,
                "this machine hands out files only: running commands is switched off",
            ));
        }
        if command.trim().is_empty() {
            return Err(Failure::invalid("command is empty"));
        }
        let timeout = Duration::from_millis(match timeout_ms {
            0 => self.limits.exec_timeout_secs * 1000,
            asked => asked.min(self.limits.exec_max_timeout_secs * 1000),
        });
        let dir = match cwd {
            Some(dir) => Some(self.resolve(None, dir)?),
            None => None,
        };

        let spawn = |program: &str| {
            let mut cmd = Command::new(program);
            harden(&mut cmd);
            if let Some(dir) = &dir {
                cmd.current_dir(dir);
            }
            cmd.arg("-c")
                .arg(command)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
        };
        // PATH сервисного окружения бывает без шелла, /bin/sh же есть везде
        let mut child = match spawn("sh") {
            Ok(child) => child,
            Err(error) if error.kind() == io::ErrorKind::NotFound => spawn("/bin/sh")
                .map_err(|error| Failure::new(Code::Io, format!("failed to run a shell: {error}")))?,
            Err(error) => {
                return Err(Failure::new(Code::Io, format!("failed to run a shell: {error}")));
            }
        };
        // вход кормим отдельной задачей: команда, пишущая много в вывод,
        // иначе упёрлась бы в непрочитанную трубу, а мы — в её вход
        let pipe = child.stdin.take();
        tokio::spawn(async move {
            if let Some(mut pipe) = pipe {
                let _ = pipe.write_all(&stdin).await;
            }
        });

        let output = tokio::time::timeout(timeout, child.wait_with_output())
            .await
            .map_err(|_| {
                Failure::new(
                    Code::Timeout,
                    format!("the command was still running after {:?}, so it was killed", timeout),
                )
            })?
            .map_err(|error| Failure::new(Code::Io, format!("the command failed: {error}")))?;

        Ok((
            Answer::Exec {
                code: output.status.code(),
                stdout: cap(&String::from_utf8_lossy(&output.stdout), self.limits.max_output),
                stderr: cap(&String::from_utf8_lossy(&output.stderr), self.limits.max_output),
            },
            Vec::new(),
        ))
    }

    fn check_size(&self, path: &Path, size: u64) -> Result<(), Failure> {
        if size > self.limits.max_write {
            return Err(Failure::new(
                Code::TooLarge,
                format!(
                    "{}: {size} bytes offered, this machine takes at most {} per write",
                    path.display(),
                    self.limits.max_write
                ),
            ));
        }
        Ok(())
    }
}

async fn write_temp(temp: &Path, data: &[u8], mode: Option<u32>) -> Result<(), Failure> {
    let mut file = fs::File::create(temp).await.map_err(|error| io_fail(temp, &error))?;
    file.write_all(data).await.map_err(|error| io_fail(temp, &error))?;
    // на диск до подмены: иначе после падения машины на месте файла может
    // оказаться его новая длина со старым содержимым
    file.sync_all().await.map_err(|error| io_fail(temp, &error))?;
    drop(file);
    if let Some(mode) = mode {
        fs::set_permissions(temp, PermissionsExt::from_mode(mode))
            .await
            .map_err(|error| io_fail(temp, &error))?;
    }
    Ok(())
}

async fn entry_at(path: &Path) -> Result<Entry, Failure> {
    let meta = fs::symlink_metadata(path)
        .await
        .map_err(|error| io_fail(path, &error))?;
    let kind = if meta.is_symlink() {
        Kind::Symlink
    } else if meta.is_dir() {
        Kind::Dir
    } else if meta.is_file() {
        Kind::File
    } else {
        Kind::Other
    };
    let target = match kind {
        Kind::Symlink => fs::read_link(path)
            .await
            .ok()
            .map(|to| to.to_string_lossy().into_owned()),
        _ => None,
    };
    // у симлинка спрашиваем длину цели: «сколько там байт» — вопрос про
    // файл, а не про запись каталога
    let size = match kind {
        Kind::Symlink => fs::metadata(path).await.map(|meta| meta.len()).unwrap_or(0),
        _ => meta.len(),
    };
    Ok(Entry {
        name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned()),
        kind,
        size,
        mode: meta.permissions().mode() & 0o7777,
        mtime: meta
            .modified()
            .ok()
            .and_then(|at| at.duration_since(UNIX_EPOCH).ok())
            .map(|since| since.as_secs() as i64),
        target,
    })
}

/// Ошибка файловой системы с кодом, по которому спрашивающий отличит
/// «файла нет» от «слишком велик» — и не выдаст пустоту за содержимое.
fn io_fail(path: &Path, error: &io::Error) -> Failure {
    let code = match error.kind() {
        io::ErrorKind::NotFound => Code::NotFound,
        io::ErrorKind::PermissionDenied => Code::Denied,
        io::ErrorKind::IsADirectory => Code::NotAFile,
        io::ErrorKind::NotADirectory => Code::NotADir,
        _ => Code::Io,
    };
    Failure::new(code, format!("{}: {error}", path.display()))
}

fn expand_home(path: &str) -> PathBuf {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return PathBuf::from(path);
    };
    if path == "~" {
        return home;
    }
    match path.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(path),
    }
}

/// Разобрать `.` и `..` не трогая диск: путь может вести к тому, чего ещё
/// нет, а изгородь корней всё равно должна сработать.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

fn cap(text: &str, max: usize) -> String {
    match text.char_indices().nth(max) {
        Some((cut, _)) => format!("{}\n[truncated at {max} chars]", &text[..cut]),
        None => text.to_owned(),
    }
}

/// Терминала здесь нет: `git log` уходит в пейджер и ждёт нажатия, git
/// просит пароль, curses мусорит escape-последовательностями в выхлоп,
/// который потом читает модель. Дешевле сказать всем сразу, что мы не
/// терминал.
fn harden(cmd: &mut Command) {
    cmd.env("PAGER", "cat")
        .env("GIT_PAGER", "cat")
        .env("TERM", "dumb")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("DEBIAN_FRONTEND", "noninteractive")
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Свой каталог на тест: временные файлы соседних тестов не должны
    /// путаться под ногами.
    struct Sandbox(PathBuf);

    impl Sandbox {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("eva-hands-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn ops() -> Ops {
        Ops::new(Limits::default())
    }

    async fn read_all(ops: &Ops, path: &str) -> Vec<u8> {
        ops.read(Path::new(path), 0, None).await.unwrap().1
    }

    #[tokio::test]
    async fn write_read_and_window() {
        let dir = Sandbox::new("window");
        let ops = ops();
        let path = dir.path("nested/data.bin");

        // запись создаёт каталог по дороге
        assert_eq!(ops.write(Path::new(&path), b"hello world", true, None).await.unwrap(), 11);
        assert_eq!(read_all(&ops, &path).await, b"hello world");

        let (total, slice) = ops.read(Path::new(&path), 6, Some(5)).await.unwrap();
        assert_eq!((total, slice), (11, b"world".to_vec()));
        // окно за концом файла — пусто, но длина честная
        let (total, slice) = ops.read(Path::new(&path), 99, Some(5)).await.unwrap();
        assert_eq!((total, slice.len()), (11, 0));
        // просят больше, чем осталось — отдаём остаток
        let (_, slice) = ops.read(Path::new(&path), 9, Some(500)).await.unwrap();
        assert_eq!(slice, b"ld".to_vec());
    }

    #[tokio::test]
    async fn write_at_patches_and_truncates() {
        let dir = Sandbox::new("write-at");
        let ops = ops();
        let path = dir.path("save.dat");
        ops.write(Path::new(&path), b"HELLO world", true, None).await.unwrap();

        // патч по смещению не меняет длину
        assert_eq!(ops.write_at(Path::new(&path), 0, b"salut", false).await.unwrap(), 11);
        assert_eq!(read_all(&ops, &path).await, b"salut world");
        // с усечением — обрубает хвост ровно после записанного
        assert_eq!(ops.write_at(Path::new(&path), 5, b"!", true).await.unwrap(), 6);
        assert_eq!(read_all(&ops, &path).await, b"salut!");
        // запись за концом растягивает файл
        assert_eq!(ops.write_at(Path::new(&path), 8, b"xx", false).await.unwrap(), 10);
    }

    #[tokio::test]
    async fn write_keeps_the_old_file_when_it_fails() {
        let dir = Sandbox::new("atomic");
        let ops = ops();
        let path = dir.path("keep.txt");
        ops.write(Path::new(&path), b"old", true, None).await.unwrap();

        // каталога нет и создавать не просили — прежний файл цел, временный
        // не остался
        let missing = dir.path("gone/keep.txt");
        assert!(ops.write(Path::new(&missing), b"new", false, None).await.is_err());
        assert_eq!(read_all(&ops, &path).await, b"old");
        let leftovers: Vec<_> = std::fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".eva-hands."))
            .collect();
        assert!(leftovers.is_empty(), "остался мусор: {leftovers:?}");
    }

    #[tokio::test]
    async fn missing_file_is_not_an_empty_one() {
        let ops = ops();
        let failure = ops.read(Path::new("/nonexistent/eva/nope"), 0, None).await.unwrap_err();
        assert_eq!(failure.code, Code::NotFound);
        assert!(failure.message.to_lowercase().contains("no such file"), "{failure}");

        let failure = ops.find(Path::new("/nonexistent/eva/nope"), b"x", 0, 8, CHUNK).await.unwrap_err();
        assert_eq!(failure.code, Code::NotFound);
    }

    #[tokio::test]
    async fn find_spans_the_window_boundary() {
        let dir = Sandbox::new("find");
        let ops = ops();
        let path = dir.path("archive.bin");
        // образец лежит ровно на стыке окон: без перекрытия он потерялся бы
        let mut data = vec![b'.'; 30];
        data[14..18].copy_from_slice(b"EVA!");
        data[24..28].copy_from_slice(b"EVA!");
        ops.write(Path::new(&path), &data, true, None).await.unwrap();

        let (total, hits, stopped) = ops.find(Path::new(&path), b"EVA!", 0, 10, 16).await.unwrap();
        assert_eq!((total, hits, stopped), (30, vec![14, 24], false));

        // поиск с середины отдаёт смещения от начала файла, а не от окна
        let (_, hits, _) = ops.find(Path::new(&path), b"EVA!", 20, 10, 16).await.unwrap();
        assert_eq!(hits, vec![24]);

        // набрав лимит, обрываем чтение и честно говорим об этом
        let (_, hits, stopped) = ops.find(Path::new(&path), b"EVA!", 0, 1, 16).await.unwrap();
        assert_eq!((hits, stopped), (vec![14], true));

        // пустой образец нашёлся бы всюду — это не поиск
        assert_eq!(
            ops.find(Path::new(&path), b"", 0, 10, 16).await.unwrap_err().code,
            Code::Invalid
        );
    }

    #[tokio::test]
    async fn find_survives_a_window_smaller_than_the_pattern() {
        let dir = Sandbox::new("find-tiny");
        let ops = ops();
        let path = dir.path("tiny.bin");
        ops.write(Path::new(&path), b"..LONGPATTERN..", true, None).await.unwrap();
        let (_, hits, _) = ops.find(Path::new(&path), b"LONGPATTERN", 0, 4, 2).await.unwrap();
        assert_eq!(hits, vec![2]);
    }

    #[tokio::test]
    async fn stat_and_list_tell_kind_and_size() {
        let dir = Sandbox::new("stat");
        let ops = ops();
        ops.write(Path::new(&dir.path("a.txt")), b"abc", true, None).await.unwrap();
        ops.write(Path::new(&dir.path("sub/b.txt")), b"defg", true, None).await.unwrap();

        let entry = entry_at(Path::new(&dir.path("a.txt"))).await.unwrap();
        assert_eq!((entry.name.as_str(), entry.kind, entry.size), ("a.txt", Kind::File, 3));

        let (entries, stopped) = ops.list(&dir.0).await.unwrap();
        assert!(!stopped);
        let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "sub"]);
        assert_eq!(entries[1].kind, Kind::Dir);
    }

    #[tokio::test]
    async fn remove_rename_and_mkdir() {
        let dir = Sandbox::new("housekeeping");
        let ops = ops();
        let from = dir.path("one.txt");
        let to = dir.path("two.txt");
        ops.write(Path::new(&from), b"x", true, None).await.unwrap();

        let renamed = Request {
            id: 1,
            cwd: None,
            op: Op::Rename { from: from.clone(), to: to.clone() },
        };
        ops.run(renamed, Vec::new()).await.unwrap();
        assert_eq!(read_all(&ops, &to).await, b"x");

        let made = Request {
            id: 2,
            cwd: Some(dir.0.to_string_lossy().into_owned()),
            op: Op::Mkdir { path: "made/deeper".into(), parents: true },
        };
        ops.run(made, Vec::new()).await.unwrap();
        assert_eq!(entry_at(&dir.0.join("made/deeper")).await.unwrap().kind, Kind::Dir);
        ops.remove(Path::new(&to), false).await.unwrap();
        assert_eq!(ops.read(Path::new(&to), 0, None).await.unwrap_err().code, Code::NotFound);

        // непустой каталог без recursive не сносится, с ним — сносится
        ops.write(Path::new(&dir.path("tree/deep/f")), b"y", true, None).await.unwrap();
        assert!(ops.remove(Path::new(&dir.path("tree")), false).await.is_err());
        ops.remove(Path::new(&dir.path("tree")), true).await.unwrap();
    }

    #[tokio::test]
    async fn roots_fence_and_dots_do_not_climb_out() {
        let dir = Sandbox::new("roots");
        let ops = Ops::new(Limits { roots: vec![dir.0.clone()], ..Limits::default() });

        let inside = ops.resolve(None, &dir.path("ok.txt")).unwrap();
        assert!(inside.starts_with(&dir.0));
        // выбраться через .. нельзя: путь разбирается до проверки
        let out = ops.resolve(None, &dir.path("../../etc/passwd")).unwrap_err();
        assert_eq!(out.code, Code::Denied);
        assert_eq!(ops.resolve(None, "/etc/passwd").unwrap_err().code, Code::Denied);
        assert_eq!(ops.resolve(None, "  ").unwrap_err().code, Code::Invalid);
    }

    #[tokio::test]
    async fn relative_paths_lean_on_the_working_directory() {
        let dir = Sandbox::new("cwd");
        let ops = ops();
        let at = ops.resolve(Some(&dir.0.to_string_lossy()), "sub/file.txt").unwrap();
        assert_eq!(at, dir.0.join("sub/file.txt"));
    }

    #[tokio::test]
    async fn read_cap_says_the_size_instead_of_handing_out_a_gigabyte() {
        let dir = Sandbox::new("cap");
        let ops = Ops::new(Limits { max_read: 4, ..Limits::default() });
        let path = dir.path("big.bin");
        Ops::new(Limits::default())
            .write(Path::new(&path), b"0123456789", true, None)
            .await
            .unwrap();
        let failure = ops.read(Path::new(&path), 0, None).await.unwrap_err();
        assert_eq!(failure.code, Code::TooLarge);
        assert!(failure.message.contains("10 bytes"), "{failure}");
    }

    #[tokio::test]
    async fn exec_runs_reports_and_can_be_switched_off() {
        let ops = ops();
        let (answer, _) = ops
            .run(
                Request {
                    id: 1,
                    cwd: None,
                    op: Op::Exec { command: "cat; echo done".into(), timeout_ms: 10_000 },
                },
                b"fed in".to_vec(),
            )
            .await
            .unwrap();
        let Answer::Exec { code, stdout, .. } = answer else { panic!("exec") };
        assert_eq!(code, Some(0));
        assert_eq!(stdout, "fed indone\n");

        let (answer, _) = ops
            .run(
                Request { id: 2, cwd: None, op: Op::Exec { command: "exit 3".into(), timeout_ms: 10_000 } },
                Vec::new(),
            )
            .await
            .unwrap();
        let Answer::Exec { code, .. } = answer else { panic!("exec") };
        assert_eq!(code, Some(3));

        let quiet = Ops::new(Limits { exec: false, ..Limits::default() });
        let failure = quiet
            .run(
                Request { id: 3, cwd: None, op: Op::Exec { command: "true".into(), timeout_ms: 0 } },
                Vec::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(failure.code, Code::Unsupported);
    }

    #[tokio::test]
    async fn exec_timeout_is_an_error_not_an_empty_answer() {
        let ops = ops();
        let failure = ops
            .run(
                Request { id: 1, cwd: None, op: Op::Exec { command: "sleep 5".into(), timeout_ms: 150 } },
                Vec::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(failure.code, Code::Timeout);
    }
}
