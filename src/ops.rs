//! The operations engine: filesystem and processes, no network and no frames.
//!
//! The same code runs in the daemon and in-process for the local machine, so
//! the behaviour is identical either way.

use std::io::SeekFrom;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::process::Command;

use crate::limits::Limits;
use crate::proto::{Answer, Code, Entry, Failure, Kind, Op, Request};
use crate::session::Sessions;

/// Search window; matches on a window boundary are preserved by overlapping the
/// next window by `pattern.len() - 1`.
const CHUNK: usize = 1024 * 1024;

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

pub struct Ops {
    pub limits: Limits,
    sessions: Arc<Sessions>,
}

type Outcome = Result<(Answer, Vec<u8>), Failure>;

impl Ops {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            sessions: Sessions::new(),
        }
    }

    pub async fn run(&self, request: Request, body: Vec<u8>) -> Outcome {
        let cwd = request.cwd.as_deref();
        match request.op {
            Op::Ping => Ok((Answer::Pong, Vec::new())),
            Op::Stat { path } => {
                let path = self.resolve(cwd, &path)?;
                Ok((
                    Answer::Stat {
                        entry: entry_at(&path).await?,
                    },
                    Vec::new(),
                ))
            }
            Op::List { path } => self.list(cwd, &path).await,
            Op::Read { path, offset, len } => self.read(cwd, &path, offset, len).await,
            Op::Write {
                path,
                create_dirs,
                mode,
            } => self.write(cwd, &path, &body, create_dirs, mode).await,
            Op::WriteAt {
                path,
                offset,
                truncate,
            } => self.write_at(cwd, &path, offset, &body, truncate).await,
            Op::Fetch {
                url,
                path,
                proxy,
                max_bytes,
                timeout_ms,
            } => {
                self.fetch(cwd, &url, &path, proxy.as_deref(), max_bytes, timeout_ms)
                    .await
            }
            Op::Find { path, from, limit } => self.find(cwd, &path, &body, from, limit).await,
            Op::Mkdir { path, parents } => self.mkdir(cwd, &path, parents).await,
            Op::Remove { path, recursive } => self.remove(cwd, &path, recursive).await,
            Op::Rename { from, to } => self.rename(cwd, &from, &to).await,
            Op::Exec {
                command,
                timeout_ms,
            } => self.exec(cwd, &command, timeout_ms, body).await,
            Op::ExecStart { command } => {
                let id = self.sessions.start(&self.limits, cwd, &command, body)?;
                Ok((Answer::Started { session: id }, Vec::new()))
            }
            Op::ExecPoll {
                session,
                max_wait_ms,
            } => {
                let handle = self
                    .sessions
                    .get(session)
                    .ok_or_else(|| Failure::new(Code::NotFound, "no such session"))?;
                let (stdout, stderr, alive, code) =
                    handle.poll(Duration::from_millis(max_wait_ms)).await;
                let mut body = Vec::with_capacity(4 + stdout.len() + stderr.len());
                body.extend_from_slice(&(stdout.len() as u32).to_be_bytes());
                body.extend_from_slice(&stdout);
                body.extend_from_slice(&stderr);
                Ok((Answer::Chunk { alive, code }, body))
            }
            Op::ExecInput { session } => {
                let handle = self
                    .sessions
                    .get(session)
                    .ok_or_else(|| Failure::new(Code::NotFound, "no such session"))?;
                handle.write_stdin(&body).await?;
                Ok((Answer::Done, Vec::new()))
            }
            Op::ExecKill { session } => {
                if let Some(handle) = self.sessions.get(session) {
                    handle.kill();
                }
                Ok((Answer::Done, Vec::new()))
            }
        }
    }

    fn resolve(&self, cwd: Option<&str>, path: &str) -> Result<PathBuf, Failure> {
        if path.is_empty() {
            return Err(Failure::invalid("empty path"));
        }
        let expanded = expand_home(path);
        let joined = if expanded.is_absolute() {
            expanded
        } else if let Some(cwd) = cwd {
            expand_home(cwd).join(expanded)
        } else {
            std::env::current_dir()
                .map_err(|e| Failure::new(Code::Io, format!("no working directory: {e}")))?
                .join(expanded)
        };
        let normal = normalize(&joined);
        if !self.limits.allows(&normal) {
            return Err(Failure::new(
                Code::Denied,
                format!("{} is outside the allowed roots", normal.display()),
            ));
        }
        Ok(normal)
    }

    async fn read(
        &self,
        cwd: Option<&str>,
        path: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Outcome {
        let path = self.resolve(cwd, path)?;
        let meta = fs::metadata(&path).await.map_err(|e| io_fail(&path, e))?;
        if meta.is_dir() {
            return Err(Failure::new(Code::NotAFile, "is a directory"));
        }
        let total = meta.len();
        let offset = offset.min(total);
        let remaining = total - offset;
        let want = len.map(|l| l.min(remaining)).unwrap_or(remaining);
        if want > self.limits.max_read {
            return Err(Failure::new(
                Code::TooLarge,
                format!("read of {want} bytes exceeds max_read {}", self.limits.max_read),
            ));
        }

        let mut file = fs::File::open(&path).await.map_err(|e| io_fail(&path, e))?;
        if offset > 0 {
            file.seek(SeekFrom::Start(offset))
                .await
                .map_err(|e| io_fail(&path, e))?;
        }
        let mut buf = Vec::with_capacity(want as usize);
        file.take(want)
            .read_to_end(&mut buf)
            .await
            .map_err(|e| io_fail(&path, e))?;

        Ok((Answer::Read { total, offset }, buf))
    }

    async fn write(
        &self,
        cwd: Option<&str>,
        path: &str,
        data: &[u8],
        create_dirs: bool,
        mode: Option<u32>,
    ) -> Outcome {
        let path = self.resolve(cwd, path)?;
        if data.len() as u64 > self.limits.max_write {
            return Err(Failure::new(
                Code::TooLarge,
                format!(
                    "write of {} bytes exceeds max_write {}",
                    data.len(),
                    self.limits.max_write
                ),
            ));
        }
        if create_dirs
            && let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|e| io_fail(parent, e))?;
            }

        let keep_mode = mode.or_else(|| existing_mode(&path));
        let tmp = temp_sibling(&path);

        let write_temp = async {
            let mut file = fs::File::create(&tmp).await?;
            file.write_all(data).await?;
            file.sync_all().await?;
            #[cfg(unix)]
            if let Some(mode) = keep_mode {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(std::fs::Permissions::from_mode(mode))
                    .await?;
            }
            Ok::<(), std::io::Error>(())
        };
        if let Err(e) = write_temp.await {
            let _ = fs::remove_file(&tmp).await;
            return Err(io_fail(&tmp, e));
        }
        if let Err(e) = fs::rename(&tmp, &path).await {
            let _ = fs::remove_file(&tmp).await;
            return Err(io_fail(&path, e));
        }
        let _ = keep_mode;

        Ok((
            Answer::Wrote {
                total: data.len() as u64,
            },
            Vec::new(),
        ))
    }

    async fn fetch(
        &self,
        cwd: Option<&str>,
        url: &str,
        path: &str,
        proxy: Option<&str>,
        max_bytes: u64,
        timeout_ms: u64,
    ) -> Outcome {
        if !self.limits.fetch {
            return Err(Failure::new(Code::Unsupported, "fetch is disabled"));
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(Failure::invalid(format!("{url} is not an http(s) url")));
        }
        // The trailing slash is the only thing that says "directory", and
        // normalisation eats it — read it off the request, not off the path.
        let into_dir = path.ends_with('/');
        let target = self.resolve(cwd, path)?;

        let cap = match max_bytes {
            0 => self.limits.max_write,
            n => n.min(self.limits.max_write),
        };
        let timeout = Duration::from_millis(match timeout_ms {
            0 => crate::proto::FETCH_TIMEOUT_MS,
            ms => ms,
        });

        let mut builder = reqwest::Client::builder().timeout(timeout);
        if let Some(proxy) = proxy {
            let proxy = reqwest::Proxy::all(proxy)
                .map_err(|e| Failure::invalid(format!("bad proxy: {e}")))?;
            builder = builder.proxy(proxy);
        }
        let client = builder
            .build()
            .map_err(|e| Failure::new(Code::Io, format!("http client: {e}")))?;

        let mut response = client.get(url).send().await.map_err(fetch_fail)?;
        let status = response.status();
        if !status.is_success() {
            return Err(Failure::new(
                status_fail(status),
                format!("{url} answered {status}"),
            ));
        }
        if let Some(len) = response.content_length()
            && len > cap {
                return Err(Failure::new(
                    Code::TooLarge,
                    format!("body of {len} bytes exceeds {cap}"),
                ));
            }

        let media_type = header(&response, reqwest::header::CONTENT_TYPE)
            .map(|value| value.split(';').next().unwrap_or_default().trim().to_owned())
            .filter(|value| !value.is_empty());
        let final_url = response.url().to_string();
        let path = if into_dir {
            let name = header(&response, reqwest::header::CONTENT_DISPOSITION)
                .and_then(disposition_name)
                .unwrap_or_else(|| url_leaf(response.url()));
            target.join(leaf_name(&name))
        } else {
            target
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| io_fail(parent, e))?;
        }
        let tmp = temp_sibling(&path);
        let stream = async {
            let mut file = fs::File::create(&tmp).await.map_err(|e| io_fail(&tmp, e))?;
            let mut total = 0u64;
            while let Some(chunk) = response.chunk().await.map_err(fetch_fail)? {
                total += chunk.len() as u64;
                if total > cap {
                    return Err(Failure::new(
                        Code::TooLarge,
                        format!("body exceeds {cap} bytes"),
                    ));
                }
                file.write_all(&chunk).await.map_err(|e| io_fail(&tmp, e))?;
            }
            file.sync_all().await.map_err(|e| io_fail(&tmp, e))?;
            Ok(total)
        };
        let total = match stream.await {
            Ok(total) => total,
            Err(failure) => {
                let _ = fs::remove_file(&tmp).await;
                return Err(failure);
            }
        };
        if let Err(e) = fs::rename(&tmp, &path).await {
            let _ = fs::remove_file(&tmp).await;
            return Err(io_fail(&path, e));
        }

        Ok((
            Answer::Fetched {
                total,
                path: path.to_string_lossy().into_owned(),
                final_url,
                media_type,
            },
            Vec::new(),
        ))
    }

    async fn write_at(
        &self,
        cwd: Option<&str>,
        path: &str,
        offset: u64,
        data: &[u8],
        truncate: bool,
    ) -> Outcome {
        let path = self.resolve(cwd, path)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .await
            .map_err(|e| io_fail(&path, e))?;
        file.seek(SeekFrom::Start(offset))
            .await
            .map_err(|e| io_fail(&path, e))?;
        file.write_all(data).await.map_err(|e| io_fail(&path, e))?;
        let end = offset + data.len() as u64;
        if truncate {
            file.set_len(end).await.map_err(|e| io_fail(&path, e))?;
        }
        file.flush().await.map_err(|e| io_fail(&path, e))?;

        let total = file.metadata().await.map(|m| m.len()).unwrap_or(end);
        Ok((Answer::Wrote { total }, Vec::new()))
    }

    async fn find(
        &self,
        cwd: Option<&str>,
        path: &str,
        pattern: &[u8],
        from: u64,
        limit: u64,
    ) -> Outcome {
        if pattern.is_empty() {
            return Err(Failure::invalid("empty search pattern"));
        }
        if limit == 0 {
            return Err(Failure::invalid("zero search limit"));
        }
        let limit = limit.min(self.limits.max_hits);
        let path = self.resolve(cwd, path)?;
        let meta = fs::metadata(&path).await.map_err(|e| io_fail(&path, e))?;
        if meta.is_dir() {
            return Err(Failure::new(Code::NotAFile, "is a directory"));
        }

        let mut file = fs::File::open(&path).await.map_err(|e| io_fail(&path, e))?;
        if from > 0 {
            file.seek(SeekFrom::Start(from))
                .await
                .map_err(|e| io_fail(&path, e))?;
        }

        let finder = memchr::memmem::Finder::new(pattern);
        let overlap = pattern.len() - 1;
        let mut offsets = Vec::new();
        let mut stopped = false;
        let mut base = from;
        let mut window: Vec<u8> = Vec::with_capacity(CHUNK + overlap);

        loop {
            let carry = window.len();
            window.resize(carry + CHUNK, 0);
            let n = file
                .read(&mut window[carry..])
                .await
                .map_err(|e| io_fail(&path, e))?;
            window.truncate(carry + n);
            if window.is_empty() {
                break;
            }

            for pos in finder.find_iter(&window) {
                offsets.push(base + pos as u64);
                if offsets.len() as u64 >= limit {
                    stopped = true;
                    break;
                }
            }
            if stopped || n == 0 {
                break;
            }

            // Keep the last `overlap` bytes so a match spanning the boundary is
            // not lost; advance `base` past what we drop.
            let keep = overlap.min(window.len());
            let drop = window.len() - keep;
            base += drop as u64;
            window.drain(..drop);
        }

        let total = offsets.len() as u64;
        Ok((
            Answer::Find {
                total,
                offsets,
                stopped,
            },
            Vec::new(),
        ))
    }

    async fn list(&self, cwd: Option<&str>, path: &str) -> Outcome {
        let path = self.resolve(cwd, path)?;
        let mut dir = fs::read_dir(&path).await.map_err(|e| io_fail(&path, e))?;
        let mut entries = Vec::new();
        let mut stopped = false;
        while let Some(item) = dir.next_entry().await.map_err(|e| io_fail(&path, e))? {
            if entries.len() as u64 >= self.limits.max_hits {
                stopped = true;
                break;
            }
            if let Ok(entry) = entry_at(&item.path()).await {
                entries.push(entry);
            }
        }
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        Ok((Answer::List { entries, stopped }, Vec::new()))
    }

    async fn mkdir(&self, cwd: Option<&str>, path: &str, parents: bool) -> Outcome {
        let path = self.resolve(cwd, path)?;
        let res = if parents {
            fs::create_dir_all(&path).await
        } else {
            fs::create_dir(&path).await
        };
        res.map_err(|e| io_fail(&path, e))?;
        Ok((Answer::Done, Vec::new()))
    }

    async fn remove(&self, cwd: Option<&str>, path: &str, recursive: bool) -> Outcome {
        let path = self.resolve(cwd, path)?;
        let meta = fs::symlink_metadata(&path)
            .await
            .map_err(|e| io_fail(&path, e))?;
        let res = if meta.is_dir() {
            if recursive {
                fs::remove_dir_all(&path).await
            } else {
                fs::remove_dir(&path).await
            }
        } else {
            fs::remove_file(&path).await
        };
        res.map_err(|e| io_fail(&path, e))?;
        Ok((Answer::Done, Vec::new()))
    }

    async fn rename(&self, cwd: Option<&str>, from: &str, to: &str) -> Outcome {
        let from = self.resolve(cwd, from)?;
        let to = self.resolve(cwd, to)?;
        fs::rename(&from, &to).await.map_err(|e| io_fail(&from, e))?;
        Ok((Answer::Done, Vec::new()))
    }

    async fn exec(
        &self,
        cwd: Option<&str>,
        command: &str,
        timeout_ms: u64,
        stdin: Vec<u8>,
    ) -> Outcome {
        if !self.limits.exec {
            return Err(Failure::new(Code::Unsupported, "exec is disabled"));
        }
        if command.trim().is_empty() {
            return Err(Failure::invalid("empty command"));
        }

        let requested = if timeout_ms == 0 {
            self.limits.exec_timeout_secs * 1000
        } else {
            timeout_ms
        };
        let cap = self.limits.exec_max_timeout_secs * 1000;
        let timeout = Duration::from_millis(requested.min(cap));

        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(command);
        if let Some(cwd) = cwd {
            cmd.current_dir(expand_home(cwd));
        }
        harden(&mut cmd);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = match cmd.spawn() {
            Ok(child) => child,
            // Bare systemd units may not have `sh` on PATH.
            Err(_) => {
                let mut cmd = Command::new("/bin/sh");
                cmd.arg("-c").arg(command);
                if let Some(cwd) = cwd {
                    cmd.current_dir(expand_home(cwd));
                }
                harden(&mut cmd);
                cmd.stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                cmd.spawn()
                    .map_err(|e| Failure::new(Code::Io, format!("failed to spawn shell: {e}")))?
            }
        };

        // Feed stdin from a separate task so a large input can't deadlock against
        // the child filling its stdout pipe.
        if let Some(mut sink) = child.stdin.take() {
            tokio::spawn(async move {
                let _ = sink.write_all(&stdin).await;
                let _ = sink.shutdown().await;
            });
        }

        let wait = child.wait_with_output();
        let output = match tokio::time::timeout(timeout, wait).await {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => return Err(Failure::new(Code::Io, format!("exec failed: {e}"))),
            Err(_) => {
                return Err(Failure::new(
                    Code::Timeout,
                    format!("command timed out after {} ms", timeout.as_millis()),
                ));
            }
        };

        let cap = self.limits.max_output as usize;
        Ok((
            Answer::Exec {
                code: output.status.code(),
                stdout: clamp(&output.stdout, cap),
                stderr: clamp(&output.stderr, cap),
            },
            Vec::new(),
        ))
    }
}

pub(crate) fn harden(cmd: &mut Command) {
    for (k, v) in [
        ("PAGER", "cat"),
        ("GIT_PAGER", "cat"),
        ("TERM", "dumb"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("DEBIAN_FRONTEND", "noninteractive"),
        ("NO_COLOR", "1"),
        ("CLICOLOR", "0"),
    ] {
        cmd.env(k, v);
    }
}

fn header(response: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<&str> {
    response.headers().get(name)?.to_str().ok()
}

fn fetch_fail(error: reqwest::Error) -> Failure {
    let code = if error.is_timeout() {
        Code::Timeout
    } else {
        Code::Io
    };
    Failure::new(code, format!("fetch failed: {error}"))
}

/// An HTTP status the caller can act on: the same distinctions the filesystem
/// codes already make, so a tool sees "gone" and "not allowed" as themselves.
fn status_fail(status: reqwest::StatusCode) -> Code {
    match status.as_u16() {
        401 | 403 => Code::Denied,
        404 | 410 => Code::NotFound,
        408 | 504 => Code::Timeout,
        413 => Code::TooLarge,
        _ => Code::Io,
    }
}

/// `filename*=UTF-8''name` wins over `filename="name"` — the former carries the
/// encoding, the latter is latin-1 at best.
fn disposition_name(value: &str) -> Option<String> {
    let mut plain = None;
    for part in value.split(';').map(str::trim) {
        if let Some(rest) = part.strip_prefix("filename*=") {
            let encoded = rest.rsplit('\'').next().unwrap_or(rest);
            return Some(percent_decode(encoded));
        }
        if let Some(rest) = part.strip_prefix("filename=") {
            plain = Some(rest.trim_matches('"').to_owned());
        }
    }
    plain
}

fn url_leaf(url: &reqwest::Url) -> String {
    let leaf = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .unwrap_or_default();
    percent_decode(leaf)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

/// A file name that cannot climb out of the directory it is joined onto.
fn leaf_name(name: &str) -> String {
    let leaf = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_start_matches('.');
    if leaf.is_empty() {
        return "download".to_owned();
    }
    leaf.to_owned()
}

fn clamp(bytes: &[u8], cap: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() <= cap {
        return text.into_owned();
    }
    let mut end = cap;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

pub(crate) fn expand_home(path: &str) -> PathBuf {
    if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home);
        }
    } else if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME") {
            return Path::new(&home).join(rest);
        }
    PathBuf::from(path)
}

/// Fold `.` and `..` lexically, without touching disk — the path may not exist
/// yet, but the fence still has to apply.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn temp_sibling(path: &Path) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let name = format!(
        ".eva-hands.{pid}.{seq}.tmp.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
    );
    match path.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

fn existing_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

async fn entry_at(path: &Path) -> Result<Entry, Failure> {
    let meta = fs::symlink_metadata(path).await.map_err(|e| io_fail(path, e))?;
    let file_type = meta.file_type();
    let (kind, size, target) = if file_type.is_symlink() {
        let target = fs::read_link(path).await.ok();
        let size = fs::metadata(path).await.map(|m| m.len()).unwrap_or(0);
        (
            Kind::Symlink,
            size,
            target.map(|t| t.to_string_lossy().into_owned()),
        )
    } else if file_type.is_dir() {
        (Kind::Dir, meta.len(), None)
    } else if file_type.is_file() {
        (Kind::File, meta.len(), None)
    } else {
        (Kind::Other, meta.len(), None)
    };

    let mode = mode_of(&meta);
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs() as i64))
        .or_else(|| {
            meta.modified()
                .ok()
                .and_then(|t| UNIX_EPOCH.duration_since(t).ok().map(|d| -(d.as_secs() as i64)))
        });

    Ok(Entry {
        name: path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        kind,
        size,
        mode,
        mtime,
        target,
    })
}

fn mode_of(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        meta.mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0
    }
}

fn io_fail(path: &Path, e: std::io::Error) -> Failure {
    use std::io::ErrorKind::*;
    let code = match e.kind() {
        NotFound => Code::NotFound,
        PermissionDenied => Code::Denied,
        _ => match e.raw_os_error() {
            Some(21) => Code::NotAFile, // EISDIR
            Some(20) => Code::NotADir,  // ENOTDIR
            _ => Code::Io,
        },
    };
    Failure::new(code, format!("{}: {e}", path.display()))
}

/// The machine's hostname, for the handshake greeting.
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Op;

    fn temp_dir() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("eva-hands-ops-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn ops() -> Ops {
        Ops::new(Limits::default())
    }

    async fn run(ops: &Ops, op: Op, body: Vec<u8>) -> Result<(Answer, Vec<u8>), Failure> {
        ops.run(
            Request {
                id: 0,
                cwd: None,
                op,
            },
            body,
        )
        .await
    }

    #[tokio::test]
    async fn write_then_read_roundtrip() {
        let dir = temp_dir();
        let path = dir.join("file.bin").to_string_lossy().into_owned();
        let ops = ops();
        let data = vec![7u8; 5000];

        let (answer, _) = run(
            &ops,
            Op::Write {
                path: path.clone(),
                create_dirs: false,
                mode: None,
            },
            data.clone(),
        )
        .await
        .unwrap();
        assert!(matches!(answer, Answer::Wrote { total: 5000 }));

        let (answer, body) = run(
            &ops,
            Op::Read {
                path: path.clone(),
                offset: 1000,
                len: Some(100),
            },
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(matches!(answer, Answer::Read { total: 5000, offset: 1000 }));
        assert_eq!(body, vec![7u8; 100]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn read_offset_past_end_is_empty() {
        let dir = temp_dir();
        let path = dir.join("f").to_string_lossy().into_owned();
        let ops = ops();
        run(
            &ops,
            Op::Write {
                path: path.clone(),
                create_dirs: false,
                mode: None,
            },
            b"hello".to_vec(),
        )
        .await
        .unwrap();

        let (answer, body) = run(
            &ops,
            Op::Read {
                path,
                offset: 100,
                len: None,
            },
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(matches!(answer, Answer::Read { total: 5, offset: 5 }));
        assert!(body.is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn write_at_and_truncate() {
        let dir = temp_dir();
        let path = dir.join("f").to_string_lossy().into_owned();
        let ops = ops();
        run(
            &ops,
            Op::Write {
                path: path.clone(),
                create_dirs: false,
                mode: None,
            },
            b"0123456789".to_vec(),
        )
        .await
        .unwrap();

        let (answer, _) = run(
            &ops,
            Op::WriteAt {
                path: path.clone(),
                offset: 4,
                truncate: true,
            },
            b"XY".to_vec(),
        )
        .await
        .unwrap();
        assert!(matches!(answer, Answer::Wrote { total: 6 }));
        assert_eq!(std::fs::read(&path).unwrap(), b"0123XY");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn find_offsets_and_limit() {
        let dir = temp_dir();
        let path = dir.join("f").to_string_lossy().into_owned();
        let ops = ops();
        run(
            &ops,
            Op::Write {
                path: path.clone(),
                create_dirs: false,
                mode: None,
            },
            b"XX__XX__XX".to_vec(),
        )
        .await
        .unwrap();

        let (answer, _) = run(
            &ops,
            Op::Find {
                path: path.clone(),
                from: 0,
                limit: 10,
            },
            b"XX".to_vec(),
        )
        .await
        .unwrap();
        match answer {
            Answer::Find { offsets, stopped, .. } => {
                assert_eq!(offsets, vec![0, 4, 8]);
                assert!(!stopped);
            }
            other => panic!("unexpected: {other:?}"),
        }

        let (answer, _) = run(
            &ops,
            Op::Find {
                path,
                from: 0,
                limit: 2,
            },
            b"XX".to_vec(),
        )
        .await
        .unwrap();
        match answer {
            Answer::Find { offsets, stopped, .. } => {
                assert_eq!(offsets, vec![0, 4]);
                assert!(stopped);
            }
            other => panic!("unexpected: {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn exec_echo_and_stdin() {
        let ops = ops();
        let (answer, _) = run(
            &ops,
            Op::Exec {
                command: "cat".into(),
                timeout_ms: 5000,
            },
            b"piped".to_vec(),
        )
        .await
        .unwrap();
        match answer {
            Answer::Exec { code, stdout, .. } => {
                assert_eq!(code, Some(0));
                assert_eq!(stdout, "piped");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn exec_timeout() {
        let ops = ops();
        let result = run(
            &ops,
            Op::Exec {
                command: "sleep 5".into(),
                timeout_ms: 200,
            },
            Vec::new(),
        )
        .await;
        assert_eq!(result.unwrap_err().code, Code::Timeout);
    }

    #[tokio::test]
    async fn roots_fence_denies_outside() {
        let dir = temp_dir();
        let limits = Limits {
            roots: vec![dir.join("allowed")],
            ..Limits::default()
        };
        let ops = Ops::new(limits);

        let outside = dir.join("elsewhere/f").to_string_lossy().into_owned();
        let result = run(
            &ops,
            Op::Write {
                path: outside,
                create_dirs: true,
                mode: None,
            },
            b"x".to_vec(),
        )
        .await;
        assert_eq!(result.unwrap_err().code, Code::Denied);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A one-shot HTTP server: answers the first request and hangs up.
    /// `headers` are appended verbatim, each ending in CRLF — leaving out
    /// `Content-Length` is what makes the body end at EOF, and that is the
    /// shape that exercises the streaming ceiling.
    async fn http_once(status: &str, headers: &str, body: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let head = format!("HTTP/1.1 {status}\r\nConnection: close\r\n{headers}\r\n");
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await;
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.shutdown().await;
        });
        format!("http://{addr}")
    }

    fn fetch(url: String, path: String, max_bytes: u64) -> Op {
        Op::Fetch {
            url,
            path,
            proxy: None,
            max_bytes,
            timeout_ms: 10_000,
        }
    }

    #[tokio::test]
    async fn fetch_streams_a_body_to_disk() {
        let dir = temp_dir();
        let path = dir.join("book.pdf").to_string_lossy().into_owned();
        let base = http_once(
            "200 OK",
            "Content-Length: 5\r\nContent-Type: application/pdf; charset=binary\r\n",
            b"%PDF!".to_vec(),
        )
        .await;

        let (answer, _) = run(&ops(), fetch(format!("{base}/x.pdf"), path.clone(), 0), Vec::new())
            .await
            .unwrap();
        match answer {
            Answer::Fetched {
                total,
                path: landed,
                media_type,
                ..
            } => {
                assert_eq!(total, 5);
                assert_eq!(landed, path);
                assert_eq!(media_type.as_deref(), Some("application/pdf"));
            }
            other => panic!("unexpected answer: {other:?}"),
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"%PDF!");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn fetch_into_a_directory_takes_the_offered_name() {
        let dir = temp_dir();
        let into = format!("{}/", dir.join("downloads").to_string_lossy());
        let base = http_once(
            "200 OK",
            "Content-Length: 2\r\nContent-Disposition: attachment; filename=\"ahmetov.pdf\"\r\n",
            b"hi".to_vec(),
        )
        .await;

        let (answer, _) = run(&ops(), fetch(format!("{base}/raw?id=7"), into, 0), Vec::new())
            .await
            .unwrap();
        let Answer::Fetched { path, .. } = answer else {
            panic!("unexpected answer: {answer:?}");
        };
        assert_eq!(path, dir.join("downloads/ahmetov.pdf").to_string_lossy());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn fetch_can_be_switched_off() {
        let ops = Ops::new(Limits {
            fetch: false,
            ..Limits::default()
        });
        let result = run(
            &ops,
            fetch("http://127.0.0.1:1/x".into(), "/tmp/x".into(), 0),
            Vec::new(),
        )
        .await;
        assert_eq!(result.unwrap_err().code, Code::Unsupported);
    }

    #[tokio::test]
    async fn fetch_stops_at_the_ceiling_and_leaves_no_temp() {
        let dir = temp_dir();
        let path = dir.join("big.bin").to_string_lossy().into_owned();
        let base = http_once("200 OK", "", vec![7u8; 4096]).await;

        let result = run(&ops(), fetch(format!("{base}/big.bin"), path, 100), Vec::new()).await;
        assert_eq!(result.unwrap_err().code, Code::TooLarge);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn fetch_reports_a_missing_url_as_missing() {
        let dir = temp_dir();
        let path = dir.join("gone.bin").to_string_lossy().into_owned();
        let base = http_once("404 Not Found", "Content-Length: 0\r\n", Vec::new()).await;

        let result = run(&ops(), fetch(format!("{base}/gone.bin"), path, 0), Vec::new()).await;
        assert_eq!(result.unwrap_err().code, Code::NotFound);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn fetch_obeys_the_roots_fence() {
        let dir = temp_dir();
        let ops = Ops::new(Limits {
            roots: vec![dir.join("allowed")],
            ..Limits::default()
        });
        let outside = dir.join("elsewhere/f").to_string_lossy().into_owned();

        let result = run(&ops, fetch("http://127.0.0.1:1/x".into(), outside, 0), Vec::new()).await;
        assert_eq!(result.unwrap_err().code, Code::Denied);
        std::fs::remove_dir_all(&dir).ok();
    }
}
