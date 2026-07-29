//! Клиент: типизированные операции над машиной, куда бы она ни была
//! подключена.
//!
//! Соединение одно и живёт долго: рукопожатие случается однажды, а не на
//! каждый чих, и все операции идут по нему вперемешку — у каждой свой `id`.
//! Когда машина своя, соединения нет вовсе: те же операции исполняются
//! прямо в процессе, и ветка «локально одно, удалённо другое» не заводится.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
};

use crate::{
    limits::Limits,
    ops::Ops,
    proto::{self, Answer, Code, Entry, Failure, Op, Reply, Request, Response},
    transport::{self, Endpoint},
};

/// Сколько ждём рукопожатия. Столько же занимает соединение с живой
/// машиной; дольше — значит, на той стороне что-то не то.
const HANDSHAKE: Duration = Duration::from_secs(20);

/// Сколько ждём ответа на файловую операцию.
const FILE_WAIT: Duration = Duration::from_secs(120);

/// Запас ожидания поверх таймаута команды: доставка, форк, обратный путь.
const EXEC_MARGIN: Duration = Duration::from_secs(15);

/// Отказ. Развилка ровно одна и она важная: руки недоступны — можно
/// пробовать другой путь; операция не удалась — это ответ машины, и врать
/// поверх него нельзя.
#[derive(Debug)]
pub enum Error {
    /// Демон не отвечает, ключ не принят или соединение оборвалось.
    Unavailable(String),
    /// Операция не удалась на той стороне.
    Failed(Failure),
}

impl Error {
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Error::Unavailable(_))
    }

    /// Код отказа операции; у недоступных рук кода нет.
    pub fn code(&self) -> Option<Code> {
        match self {
            Error::Failed(failure) => Some(failure.code),
            Error::Unavailable(_) => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unavailable(why) => write!(f, "eva-hands is out of reach: {why}"),
            Error::Failed(failure) => f.write_str(&failure.message),
        }
    }
}

impl std::error::Error for Error {}

/// Что машина сказала о себе на рукопожатии.
#[derive(Debug, Clone)]
pub struct Greeting {
    pub protocol: u32,
    pub version: String,
    pub host: String,
    pub limits: Limits,
}

/// Руки Евы: одинаковый набор операций поверх любого подключения.
pub struct Hands {
    backend: Backend,
}

impl std::fmt::Debug for Hands {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.backend {
            Backend::Local(_) => f.write_str("hands on this machine"),
            Backend::Remote(remote) => write!(f, "hands at {}", remote.endpoint.address),
            Backend::Wired(conn) => write!(f, "hands on {}", conn.greeting.host),
        }
    }
}

enum Backend {
    /// Машина своя — исполняем прямо здесь.
    Local(Arc<Ops>),
    /// Машина за сетью; соединение поднимается лениво и переживает разрывы.
    Remote(Remote),
    /// Готовое соединение — в тестах.
    Wired(Arc<Conn>),
}

impl Hands {
    /// Своя машина: без сети и без демона, теми же операциями.
    pub fn local(limits: Limits) -> Self {
        Self { backend: Backend::Local(Arc::new(Ops::new(limits))) }
    }

    /// Машина за сетью. Соединение поднимется при первой операции — здесь
    /// ничего не открывается и ничего не может упасть.
    pub fn remote(endpoint: Endpoint) -> Self {
        Self { backend: Backend::Remote(Remote { endpoint, conn: tokio::sync::Mutex::new(None) }) }
    }

    /// Готовые потоки к уже открытому каналу.
    pub async fn over<R, W>(reader: R, writer: W) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let conn = Conn::start(reader, writer, None).await?;
        Ok(Self { backend: Backend::Wired(Arc::new(conn)) })
    }

    /// Что машина сказала о себе; у своей машины рукопожатия нет.
    pub async fn greeting(&self) -> Option<Greeting> {
        match &self.backend {
            Backend::Local(_) => None,
            Backend::Wired(conn) => Some(conn.greeting.clone()),
            Backend::Remote(remote) => remote.conn().await.ok().map(|conn| conn.greeting.clone()),
        }
    }

    /// Живы ли руки. Простаивающее соединение умеет умирать молча, и
    /// спросить об этом дешевле, чем узнать посреди работы.
    pub async fn ping(&self) -> Result<(), Error> {
        self.call(None, Op::Ping, Vec::new(), HANDSHAKE).await.map(|_| ())
    }

    pub async fn stat(&self, cwd: Option<&str>, path: &str) -> Result<Entry, Error> {
        let (answer, _) = self
            .call(cwd, Op::Stat { path: path.to_owned() }, Vec::new(), FILE_WAIT)
            .await?;
        match answer {
            Answer::Stat { entry } => Ok(entry),
            other => Err(mismatch("stat", &other)),
        }
    }

    /// Содержимое каталога; `stopped` — упёрлись в потолок машины.
    pub async fn list(&self, cwd: Option<&str>, path: &str) -> Result<(Vec<Entry>, bool), Error> {
        let (answer, _) = self
            .call(cwd, Op::List { path: path.to_owned() }, Vec::new(), FILE_WAIT)
            .await?;
        match answer {
            Answer::List { entries, stopped } => Ok((entries, stopped)),
            other => Err(mismatch("list", &other)),
        }
    }

    /// Кусок файла и полная длина файла. `len` не задан — до конца.
    pub async fn read(
        &self,
        cwd: Option<&str>,
        path: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<(u64, Vec<u8>), Error> {
        let op = Op::Read { path: path.to_owned(), offset, len };
        let (answer, body) = self.call(cwd, op, Vec::new(), FILE_WAIT).await?;
        match answer {
            Answer::Read { total, .. } => Ok((total, body)),
            other => Err(mismatch("read", &other)),
        }
    }

    /// Файл целиком; возвращает новую длину.
    pub async fn write(
        &self,
        cwd: Option<&str>,
        path: &str,
        data: Vec<u8>,
        create_dirs: bool,
    ) -> Result<u64, Error> {
        let op = Op::Write { path: path.to_owned(), create_dirs, mode: None };
        self.wrote(cwd, op, data).await
    }

    /// Байты по смещению поверх существующих; `truncate` обрубает хвост.
    pub async fn write_at(
        &self,
        cwd: Option<&str>,
        path: &str,
        offset: u64,
        data: Vec<u8>,
        truncate: bool,
    ) -> Result<u64, Error> {
        let op = Op::WriteAt { path: path.to_owned(), offset, truncate };
        self.wrote(cwd, op, data).await
    }

    async fn wrote(&self, cwd: Option<&str>, op: Op, data: Vec<u8>) -> Result<u64, Error> {
        let (answer, _) = self.call(cwd, op, data, FILE_WAIT).await?;
        match answer {
            Answer::Wrote { total } => Ok(total),
            other => Err(mismatch("write", &other)),
        }
    }

    /// Смещения вхождений образца, полная длина файла и признак «оборвались
    /// на лимите». Файл читает та машина, где он лежит.
    pub async fn find(
        &self,
        cwd: Option<&str>,
        path: &str,
        pattern: &[u8],
        from: u64,
        limit: u64,
    ) -> Result<(u64, Vec<u64>, bool), Error> {
        let op = Op::Find { path: path.to_owned(), from, limit };
        let (answer, _) = self.call(cwd, op, pattern.to_vec(), FILE_WAIT).await?;
        match answer {
            Answer::Find { total, offsets, stopped } => Ok((total, offsets, stopped)),
            other => Err(mismatch("find", &other)),
        }
    }

    pub async fn mkdir(&self, cwd: Option<&str>, path: &str, parents: bool) -> Result<(), Error> {
        let op = Op::Mkdir { path: path.to_owned(), parents };
        self.call(cwd, op, Vec::new(), FILE_WAIT).await.map(|_| ())
    }

    pub async fn remove(&self, cwd: Option<&str>, path: &str, recursive: bool) -> Result<(), Error> {
        let op = Op::Remove { path: path.to_owned(), recursive };
        self.call(cwd, op, Vec::new(), FILE_WAIT).await.map(|_| ())
    }

    pub async fn rename(&self, cwd: Option<&str>, from: &str, to: &str) -> Result<(), Error> {
        let op = Op::Rename { from: from.to_owned(), to: to.to_owned() };
        self.call(cwd, op, Vec::new(), FILE_WAIT).await.map(|_| ())
    }

    /// Команда на машине. Таймаут считает та сторона — ждём его с запасом
    /// на дорогу.
    pub async fn exec(
        &self,
        cwd: Option<&str>,
        command: &str,
        timeout: Duration,
        stdin: Vec<u8>,
    ) -> Result<Output, Error> {
        let op = Op::Exec {
            command: command.to_owned(),
            timeout_ms: timeout.as_millis().min(u64::MAX as u128) as u64,
        };
        let (answer, _) = self.call(cwd, op, stdin, timeout + EXEC_MARGIN).await?;
        match answer {
            Answer::Exec { code, stdout, stderr } => Ok(Output { code, stdout, stderr }),
            other => Err(mismatch("exec", &other)),
        }
    }

    async fn call(
        &self,
        cwd: Option<&str>,
        op: Op,
        body: Vec<u8>,
        wait: Duration,
    ) -> Result<(Answer, Vec<u8>), Error> {
        match &self.backend {
            Backend::Local(ops) => {
                let request = Request { id: 0, cwd: cwd.map(str::to_owned), op };
                ops.run(request, body).await.map_err(Error::Failed)
            }
            Backend::Wired(conn) => conn.call(cwd, op, body, wait).await,
            Backend::Remote(remote) => {
                let conn = remote.conn().await?;
                // повтор только для операций, которые ничего не меняют:
                // соединение могло умереть по дороге, а переписывать файл
                // дважды из-за оборванного канала — не то, чего хочет никто
                if !retriable(&op) {
                    return conn.call(cwd, op, body, wait).await;
                }
                match conn.call(cwd, op.clone(), body.clone(), wait).await {
                    Err(Error::Unavailable(_)) => {
                        remote.forget(&conn).await;
                        let fresh = remote.conn().await?;
                        fresh.call(cwd, op, body, wait).await
                    }
                    other => other,
                }
            }
        }
    }
}

/// Выхлоп команды.
#[derive(Debug, Clone)]
pub struct Output {
    /// Пусто, если команду убил сигнал.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }
}

fn retriable(op: &Op) -> bool {
    matches!(op, Op::Ping | Op::Stat { .. } | Op::List { .. } | Op::Read { .. } | Op::Find { .. })
}

fn mismatch(asked: &str, got: &Answer) -> Error {
    Error::Unavailable(format!("asked for {asked}, the machine answered {got:?}"))
}

struct Remote {
    endpoint: Endpoint,
    conn: tokio::sync::Mutex<Option<Arc<Conn>>>,
}

impl Remote {
    /// Живое соединение: поднимаем, если его нет или оно умерло. Под
    /// замком, чтобы десять операций подряд не подняли десять соединений.
    async fn conn(&self) -> Result<Arc<Conn>, Error> {
        let mut slot = self.conn.lock().await;
        if let Some(conn) = slot.as_ref()
            && !conn.is_dead()
        {
            return Ok(conn.clone());
        }
        let link = transport::connect(&self.endpoint).await?;
        let fresh = Arc::new(Conn::start(link.reader, link.writer, Some(link.session)).await?);
        *slot = Some(fresh.clone());
        Ok(fresh)
    }

    async fn forget(&self, stale: &Arc<Conn>) {
        let mut slot = self.conn.lock().await;
        if slot.as_ref().is_some_and(|conn| Arc::ptr_eq(conn, stale)) {
            *slot = None;
        }
    }
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<(Answer, Vec<u8>), Error>>>>>;

/// Соединение с демоном: пишущая труба и ждущие ответа.
struct Conn {
    out: mpsc::Sender<(Vec<u8>, Vec<u8>)>,
    pending: Pending,
    next: AtomicU64,
    dead: Arc<AtomicBool>,
    greeting: Greeting,
    /// Живёт ради соединения: пока ручка сессии цела, цел и канал.
    _session: Option<russh::client::Handle<transport::Verifier>>,
}

impl Conn {
    async fn start<R, W>(
        mut reader: R,
        writer: W,
        session: Option<russh::client::Handle<transport::Verifier>>,
    ) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let greeting = match tokio::time::timeout(
            HANDSHAKE,
            proto::read_frame(&mut reader, proto::MAX_HEADER as u64),
        )
        .await
        {
            Ok(Ok(Some(frame))) => hello(&frame.header)?,
            Ok(Ok(None)) => return Err(Error::Unavailable("it said nothing".to_owned())),
            Ok(Err(error)) => return Err(Error::Unavailable(error.to_string())),
            Err(_) => {
                return Err(Error::Unavailable("it did not answer the handshake".to_owned()));
            }
        };
        if greeting.protocol != proto::PROTOCOL {
            return Err(Error::Unavailable(format!(
                "it speaks protocol {} while this client speaks {} — update the older side",
                greeting.protocol,
                proto::PROTOCOL
            )));
        }

        let pending: Pending = Arc::default();
        let dead = Arc::new(AtomicBool::new(false));
        let (out, mut queue) = mpsc::channel::<(Vec<u8>, Vec<u8>)>(16);

        let died = dead.clone();
        tokio::spawn(async move {
            let mut writer = writer;
            while let Some((header, body)) = queue.recv().await {
                if proto::write_frame(&mut writer, &header, &body).await.is_err() {
                    died.store(true, Ordering::Relaxed);
                    break;
                }
            }
        });

        let waiting = pending.clone();
        let died = dead.clone();
        let cap = greeting.limits.max_frame();
        tokio::spawn(async move {
            // и чистый конец, и обрыв означают одно: ответов больше не
            // будет, и ждущим надо сказать об этом, а не держать их до
            // таймаута
            while let Ok(Some(frame)) = proto::read_frame(&mut reader, cap).await {
                deliver(&waiting, frame);
            }
            died.store(true, Ordering::Relaxed);
            let orphans: Vec<_> = waiting
                .lock()
                .map(|mut waiting| waiting.drain().map(|(_, tx)| tx).collect())
                .unwrap_or_default();
            for tx in orphans {
                // оборванное соединение — не отказ операции: спрашивающий
                // вправе пойти другим путём, а не объявить файл пропавшим
                let _ = tx.send(Err(Error::Unavailable("the connection went down".to_owned())));
            }
        });

        Ok(Self { out, pending, next: AtomicU64::new(1), dead, greeting, _session: session })
    }

    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::Relaxed)
    }

    async fn call(
        &self,
        cwd: Option<&str>,
        op: Op,
        body: Vec<u8>,
        wait: Duration,
    ) -> Result<(Answer, Vec<u8>), Error> {
        if self.is_dead() {
            return Err(Error::Unavailable("the connection is closed".to_owned()));
        }
        if body.len() as u64 > self.greeting.limits.max_frame() {
            return Err(Error::Failed(Failure::new(
                Code::TooLarge,
                format!(
                    "{} bytes offered, the machine takes at most {} at once",
                    body.len(),
                    self.greeting.limits.max_write
                ),
            )));
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let request = Request { id, cwd: cwd.map(str::to_owned), op };
        let header = serde_json::to_vec(&request).expect("a request is always serialisable");

        let (tx, rx) = oneshot::channel();
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(id, tx);
        }
        if self.out.send((header, body)).await.is_err() {
            self.forget(id);
            return Err(Error::Unavailable("the connection is closed".to_owned()));
        }
        match tokio::time::timeout(wait, rx).await {
            Ok(Ok(result)) => result,
            // отправитель исчез вместе с соединением
            Ok(Err(_)) => Err(Error::Unavailable("the connection went down".to_owned())),
            Err(_) => {
                self.forget(id);
                Err(Error::Unavailable(format!(
                    "no answer in {}s — the machine may be wedged",
                    wait.as_secs()
                )))
            }
        }
    }

    fn forget(&self, id: u64) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&id);
        }
    }
}

fn deliver(pending: &Pending, frame: proto::Frame) {
    let Ok(response) = serde_json::from_slice::<Response>(&frame.header) else {
        return;
    };
    let Some(tx) = pending.lock().ok().and_then(|mut waiting| waiting.remove(&response.id)) else {
        return;
    };
    let _ = tx.send(match response.result {
        Reply::Ok(answer) => Ok((answer, frame.body)),
        Reply::Err(failure) => Err(Error::Failed(failure)),
    });
}

fn hello(header: &[u8]) -> Result<Greeting, Error> {
    let response: Response = serde_json::from_slice(header)
        .map_err(|error| Error::Unavailable(format!("its greeting made no sense: {error}")))?;
    match response.result {
        Reply::Ok(Answer::Hello { protocol, version, host, limits }) => {
            Ok(Greeting { protocol, version, host, limits })
        }
        other => Err(Error::Unavailable(format!("it greeted with {other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Руки на трубе: сервер и клиент в одном процессе, без сети.
    async fn wired() -> Hands {
        let (mine, theirs) = tokio::io::duplex(1 << 20);
        let (read, write) = tokio::io::split(theirs);
        tokio::spawn(async move {
            let _ = crate::server::serve(read, write, Arc::new(Ops::new(Limits::default()))).await;
        });
        let (read, write) = tokio::io::split(mine);
        Hands::over(read, write).await.unwrap()
    }

    fn sandbox(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("eva-hands-client-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn the_whole_stack_reads_writes_and_finds() {
        let dir = sandbox("round-trip");
        let hands = wired().await;
        let path = dir.join("data.bin").to_string_lossy().into_owned();

        assert_eq!(hands.write(None, &path, b"hello world".to_vec(), true).await.unwrap(), 11);
        let (total, bytes) = hands.read(None, &path, 0, None).await.unwrap();
        assert_eq!((total, bytes), (11, b"hello world".to_vec()));

        // окно отдаёт кусок и полную длину
        let (total, bytes) = hands.read(None, &path, 6, Some(5)).await.unwrap();
        assert_eq!((total, bytes), (11, b"world".to_vec()));

        assert_eq!(hands.write_at(None, &path, 0, b"HELLO".to_vec(), false).await.unwrap(), 11);
        assert_eq!(hands.write_at(None, &path, 5, b"!".to_vec(), true).await.unwrap(), 6);
        let (_, bytes) = hands.read(None, &path, 0, None).await.unwrap();
        assert_eq!(bytes, b"HELLO!".to_vec());

        hands.write(None, &path, b"aXbXc".to_vec(), false).await.unwrap();
        let (total, hits, stopped) = hands.find(None, &path, b"X", 0, 10).await.unwrap();
        assert_eq!((total, hits, stopped), (5, vec![1, 3], false));

        let entry = hands.stat(None, &path).await.unwrap();
        assert_eq!((entry.kind, entry.size), (crate::proto::Kind::File, 5));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_missing_file_comes_back_as_a_refusal_not_as_emptiness() {
        let hands = wired().await;
        let error = hands.read(None, "/nonexistent/eva/nope", 0, None).await.unwrap_err();
        assert_eq!(error.code(), Some(Code::NotFound));
        // отказ операции — не повод искать обходной путь
        assert!(!error.is_unavailable());
        assert!(error.to_string().to_lowercase().contains("no such file"), "{error}");
    }

    #[tokio::test]
    async fn binary_content_survives_the_wire() {
        let dir = sandbox("binary");
        let hands = wired().await;
        let path = dir.join("blob.bin").to_string_lossy().into_owned();
        // всё, что ломается о шелл: нули, кавычки, переводы строк, не-UTF8
        let data: Vec<u8> = (0u8..=255).chain(b"'\"\n\\$`".iter().copied()).collect();

        hands.write(None, &path, data.clone(), true).await.unwrap();
        let (_, back) = hands.read(None, &path, 0, None).await.unwrap();
        assert_eq!(back, data);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn answers_come_back_out_of_order() {
        let hands = Arc::new(wired().await);
        let slow = {
            let hands = hands.clone();
            tokio::spawn(async move {
                hands.exec(None, "sleep 1; echo late", Duration::from_secs(10), Vec::new()).await
            })
        };
        // пока команда спит, файловые операции обязаны отвечать
        hands.ping().await.unwrap();
        assert!(hands.stat(None, "/nonexistent/eva/nope").await.is_err());
        assert_eq!(slow.await.unwrap().unwrap().stdout.trim(), "late");
    }

    #[tokio::test]
    async fn a_machine_that_does_not_answer_is_unavailable() {
        let hands = Hands::remote(Endpoint {
            // 127.0.0.1:1 никем не занят, достучаться туда невозможно
            address: "127.0.0.1:1".into(),
            user: "eva".into(),
            key: "/nonexistent/eva/key".into(),
            host_key: None,
        });
        let error = hands.stat(None, "/etc/hosts").await.unwrap_err();
        assert!(error.is_unavailable(), "{error}");
    }

    /// «Демон», который здоровается и уходит.
    fn greeter(protocol: u32) -> tokio::io::DuplexStream {
        let (mine, mut theirs) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let hello = Response {
                id: 0,
                result: Reply::Ok(Answer::Hello {
                    protocol,
                    version: "0.0.0".into(),
                    host: "nowhere".into(),
                    limits: Limits::default(),
                }),
            };
            let header = serde_json::to_vec(&hello).unwrap();
            let _ = proto::write_frame(&mut theirs, &header, b"").await;
        });
        mine
    }

    #[tokio::test]
    async fn a_connection_that_went_down_is_unavailable_not_a_failed_operation() {
        let (read, write) = tokio::io::split(greeter(proto::PROTOCOL));
        let hands = Hands::over(read, write).await.unwrap();
        // отвечать некому: ждущий обязан узнать это, а не висеть до таймаута
        let error = hands.ping().await.unwrap_err();
        assert!(error.is_unavailable(), "{error}");
        assert!(error.code().is_none());
    }

    #[tokio::test]
    async fn a_stranger_protocol_is_refused_at_the_handshake() {
        let (read, write) = tokio::io::split(greeter(proto::PROTOCOL + 1));
        let error = Hands::over(read, write).await.unwrap_err();
        assert!(error.to_string().contains("protocol"), "{error}");
    }
}
