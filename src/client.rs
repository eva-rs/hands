//! The [`Hands`] API — one operation set, whether the work runs in-process or
//! over an encrypted connection.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use tokio::time::timeout;

use crate::limits::Limits;
use crate::ops::{Ops, hostname};
use crate::proto::{self, Answer, Code, Entry, Failure, Op, PROTOCOL, Reply, Request, Response};
use crate::secret::Psk;
use crate::transport;

const HANDSHAKE: Duration = Duration::from_secs(20);
const FILE_WAIT: Duration = Duration::from_secs(120);
const EXEC_MARGIN: Duration = Duration::from_secs(15);

const COPY_CHUNK: u64 = 1024 * 1024;

/// The one distinction the caller must not lose: `Unavailable` means the hands
/// are out of reach (daemon silent, key rejected, connection dropped) — a
/// caller may try another path. `Failed` is the machine's own honest answer to
/// the operation — it must not be smoothed over.
#[derive(Debug)]
pub enum Error {
    Unavailable(String),
    Failed(Failure),
}

impl Error {
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Error::Unavailable(_))
    }

    pub fn code(&self) -> Option<Code> {
        match self {
            Error::Failed(f) => Some(f.code),
            Error::Unavailable(_) => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unavailable(m) => write!(f, "hands unavailable: {m}"),
            Error::Failed(fl) => write!(f, "operation failed: {fl}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<Failure> for Error {
    fn from(f: Failure) -> Self {
        Error::Failed(f)
    }
}

#[derive(Clone, Debug)]
pub struct Greeting {
    pub protocol: u32,
    pub version: String,
    pub host: String,
    pub limits: Limits,
}

#[derive(Clone, Debug)]
pub struct Output {
    pub code: Option<i32>,
    pub signal: Option<String>,
    pub timed_out_ms: Option<u64>,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.code == Some(0) && self.signal.is_none() && self.timed_out_ms.is_none()
    }
}

/// What to download and where to put it. A `path` ending in `/` is a
/// directory: the machine picks the leaf name and reports it back.
#[derive(Clone, Debug)]
pub struct FetchRequest {
    pub url: String,
    pub path: String,
    pub proxy: Option<String>,
    /// Body ceiling; 0 — the machine's `max_write`.
    pub max_bytes: u64,
    /// Whole-request deadline; 0 — [`proto::FETCH_TIMEOUT_MS`].
    pub timeout_ms: u64,
}

#[derive(Clone, Debug)]
pub struct Fetched {
    pub total: u64,
    pub path: String,
    pub final_url: String,
    pub media_type: Option<String>,
}

pub struct Hands {
    backend: Backend,
}

enum Backend {
    Local(Arc<Ops>),
    Wired(Arc<Conn>),
    Remote(Remote),
}

impl Hands {
    /// In-process, no network, no handshake.
    pub fn local(limits: Limits) -> Self {
        Hands {
            backend: Backend::Local(Arc::new(Ops::new(limits))),
        }
    }

    /// A daemon reached over an encrypted channel. Nothing connects until the
    /// first operation.
    pub fn remote(addr: impl Into<String>, psk: &Psk) -> Self {
        Hands {
            backend: Backend::Remote(Remote {
                addr: addr.into(),
                psk: psk.derive32(),
                conn: AsyncMutex::new(None),
            }),
        }
    }

    /// Wire onto an already-open channel (used in tests).
    pub async fn over<S>(stream: S) -> Result<Self, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let conn = Conn::start(stream, HANDSHAKE).await?;
        Ok(Hands {
            backend: Backend::Wired(Arc::new(conn)),
        })
    }

    pub async fn greeting(&self) -> Result<Greeting, Error> {
        match &self.backend {
            Backend::Local(ops) => Ok(Greeting {
                protocol: PROTOCOL,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                host: hostname(),
                limits: ops.limits.clone(),
            }),
            Backend::Wired(conn) => Ok(conn.greeting.clone()),
            Backend::Remote(remote) => Ok(remote.conn().await?.greeting.clone()),
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
                let request = Request {
                    id: 0,
                    cwd: cwd.map(|s| s.to_owned()),
                    op,
                };
                ops.run(request, body).await.map_err(Error::Failed)
            }
            Backend::Wired(conn) => conn.call(cwd, &op, body, wait).await,
            Backend::Remote(remote) => {
                let read_only = op.is_read_only();
                let retry_body = read_only.then(|| body.clone());
                let conn = remote.conn().await?;
                match conn.call(cwd, &op, body, wait).await {
                    Err(Error::Unavailable(_)) if read_only => {
                        remote.forget().await;
                        let conn = remote.conn().await?;
                        conn.call(cwd, &op, retry_body.unwrap_or_default(), wait)
                            .await
                    }
                    other => other,
                }
            }
        }
    }

    pub async fn ping(&self, cwd: Option<&str>) -> Result<(), Error> {
        self.call(cwd, Op::Ping, Vec::new(), FILE_WAIT).await?;
        Ok(())
    }

    pub async fn stat(&self, cwd: Option<&str>, path: &str) -> Result<Entry, Error> {
        let (answer, _) = self
            .call(cwd, Op::Stat { path: path.into() }, Vec::new(), FILE_WAIT)
            .await?;
        match answer {
            Answer::Stat { entry } => Ok(entry),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn list(&self, cwd: Option<&str>, path: &str) -> Result<(Vec<Entry>, bool), Error> {
        let (answer, _) = self
            .call(cwd, Op::List { path: path.into() }, Vec::new(), FILE_WAIT)
            .await?;
        match answer {
            Answer::List { entries, stopped } => Ok((entries, stopped)),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn read(
        &self,
        cwd: Option<&str>,
        path: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<(u64, Vec<u8>), Error> {
        let (answer, body) = self
            .call(
                cwd,
                Op::Read {
                    path: path.into(),
                    offset,
                    len,
                },
                Vec::new(),
                FILE_WAIT,
            )
            .await?;
        match answer {
            Answer::Read { total, .. } => Ok((total, body)),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn write(
        &self,
        cwd: Option<&str>,
        path: &str,
        data: &[u8],
        create_dirs: bool,
        mode: Option<u32>,
    ) -> Result<u64, Error> {
        let (answer, _) = self
            .call(
                cwd,
                Op::Write {
                    path: path.into(),
                    create_dirs,
                    mode,
                },
                data.to_vec(),
                FILE_WAIT,
            )
            .await?;
        match answer {
            Answer::Wrote { total } => Ok(total),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn write_at(
        &self,
        cwd: Option<&str>,
        path: &str,
        offset: u64,
        data: &[u8],
        truncate: bool,
    ) -> Result<u64, Error> {
        let (answer, _) = self
            .call(
                cwd,
                Op::WriteAt {
                    path: path.into(),
                    offset,
                    truncate,
                },
                data.to_vec(),
                FILE_WAIT,
            )
            .await?;
        match answer {
            Answer::Wrote { total } => Ok(total),
            other => Err(unexpected(&other)),
        }
    }

    /// Download a URL onto the machine, streaming — the bytes never cross this
    /// wire, so size is bounded by the machine's `max_write`, not the frame.
    pub async fn fetch(&self, cwd: Option<&str>, req: FetchRequest) -> Result<Fetched, Error> {
        let timeout_ms = match req.timeout_ms {
            0 => proto::FETCH_TIMEOUT_MS,
            ms => ms,
        };
        let wait = Duration::from_millis(timeout_ms) + EXEC_MARGIN;
        let (answer, _) = self
            .call(
                cwd,
                Op::Fetch {
                    url: req.url,
                    path: req.path,
                    proxy: req.proxy,
                    max_bytes: req.max_bytes,
                    timeout_ms: req.timeout_ms,
                },
                Vec::new(),
                wait,
            )
            .await?;
        match answer {
            Answer::Fetched {
                total,
                path,
                final_url,
                media_type,
            } => Ok(Fetched {
                total,
                path,
                final_url,
                media_type,
            }),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn find(
        &self,
        cwd: Option<&str>,
        path: &str,
        pattern: &[u8],
        from: u64,
        limit: u64,
    ) -> Result<(u64, Vec<u64>, bool), Error> {
        let (answer, _) = self
            .call(
                cwd,
                Op::Find {
                    path: path.into(),
                    from,
                    limit,
                },
                pattern.to_vec(),
                FILE_WAIT,
            )
            .await?;
        match answer {
            Answer::Find {
                total,
                offsets,
                stopped,
            } => Ok((total, offsets, stopped)),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn mkdir(&self, cwd: Option<&str>, path: &str, parents: bool) -> Result<(), Error> {
        self.call(
            cwd,
            Op::Mkdir {
                path: path.into(),
                parents,
            },
            Vec::new(),
            FILE_WAIT,
        )
        .await?;
        Ok(())
    }

    pub async fn remove(
        &self,
        cwd: Option<&str>,
        path: &str,
        recursive: bool,
    ) -> Result<(), Error> {
        self.call(
            cwd,
            Op::Remove {
                path: path.into(),
                recursive,
            },
            Vec::new(),
            FILE_WAIT,
        )
        .await?;
        Ok(())
    }

    pub async fn rename(&self, cwd: Option<&str>, from: &str, to: &str) -> Result<(), Error> {
        self.call(
            cwd,
            Op::Rename {
                from: from.into(),
                to: to.into(),
            },
            Vec::new(),
            FILE_WAIT,
        )
        .await?;
        Ok(())
    }

    pub async fn exec(
        &self,
        cwd: Option<&str>,
        command: &str,
        timeout_ms: u64,
        stdin: Vec<u8>,
    ) -> Result<Output, Error> {
        let limits = self.greeting().await?.limits;
        let requested = if timeout_ms == 0 {
            limits.exec_timeout_secs.saturating_mul(1000)
        } else {
            timeout_ms
        };
        let effective = requested.min(limits.exec_max_timeout_secs.saturating_mul(1000));
        // Include the server's TERM grace and pipe drain so the client does
        // not give up just before a valid timed-out Exec answer arrives.
        let wait = Duration::from_millis(effective)
            .saturating_add(EXEC_MARGIN)
            .saturating_add(Duration::from_secs(3));
        let (answer, _) = self
            .call(
                cwd,
                Op::Exec {
                    command: command.into(),
                    timeout_ms,
                },
                stdin,
                wait,
            )
            .await?;
        match answer {
            Answer::Exec {
                code,
                signal,
                timed_out_ms,
                stdout,
                stderr,
            } => Ok(Output {
                code,
                signal,
                timed_out_ms,
                stdout,
                stderr,
            }),
            other => Err(unexpected(&other)),
        }
    }

    /// Start a background session and return its id. `stdin` is fed to the
    /// process immediately (may be empty).
    pub async fn exec_start(
        &self,
        cwd: Option<&str>,
        command: &str,
        stdin: Vec<u8>,
    ) -> Result<u64, Error> {
        let (answer, _) = self
            .call(
                cwd,
                Op::ExecStart {
                    command: command.into(),
                },
                stdin,
                FILE_WAIT,
            )
            .await?;
        match answer {
            Answer::Started { session } => Ok(session),
            other => Err(unexpected(&other)),
        }
    }

    /// Long-poll a session: waits up to `max_wait_ms` for new output or exit.
    /// Returns `(stdout, stderr, alive, exit_code)`.
    pub async fn exec_poll(
        &self,
        session: u64,
        max_wait_ms: u64,
    ) -> Result<(Vec<u8>, Vec<u8>, bool, Option<i32>), Error> {
        let wait = Duration::from_millis(max_wait_ms) + EXEC_MARGIN;
        let (answer, body) = self
            .call(
                None,
                Op::ExecPoll {
                    session,
                    max_wait_ms,
                },
                Vec::new(),
                wait,
            )
            .await?;
        match answer {
            Answer::Chunk { alive, code } => {
                let (stdout, stderr) = split_chunk(&body)?;
                Ok((stdout, stderr, alive, code))
            }
            other => Err(unexpected(&other)),
        }
    }

    /// Feed bytes to a session's stdin.
    pub async fn exec_input(&self, session: u64, data: Vec<u8>) -> Result<(), Error> {
        self.call(None, Op::ExecInput { session }, data, FILE_WAIT)
            .await?;
        Ok(())
    }

    /// Terminate a session and its process tree.
    pub async fn exec_kill(&self, session: u64) -> Result<(), Error> {
        self.call(None, Op::ExecKill { session }, Vec::new(), FILE_WAIT)
            .await?;
        Ok(())
    }
}

/// Split a [`Answer::Chunk`] body: `u32 stdout_len (BE) | stdout | stderr`.
fn split_chunk(body: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    if body.len() < 4 {
        return Err(Error::Failed(Failure::new(Code::Io, "short chunk body")));
    }
    let stdout_len = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let rest = &body[4..];
    if stdout_len > rest.len() {
        return Err(Error::Failed(Failure::new(
            Code::Io,
            "malformed chunk body",
        )));
    }
    Ok((rest[..stdout_len].to_vec(), rest[stdout_len..].to_vec()))
}

/// Stream a file between two hands, in either direction (local↔remote). Reads in
/// windows and writes at the matching offset, so a large file never has to sit
/// in memory whole.
pub async fn copy(
    from: &Hands,
    from_cwd: Option<&str>,
    from_path: &str,
    to: &Hands,
    to_cwd: Option<&str>,
    to_path: &str,
) -> Result<u64, Error> {
    let mut offset = 0u64;
    loop {
        let (total, data) = from
            .read(from_cwd, from_path, offset, Some(COPY_CHUNK))
            .await?;
        if data.is_empty() {
            to.write_at(to_cwd, to_path, offset, &[], true).await?;
            break;
        }
        let last = offset + data.len() as u64 >= total;
        to.write_at(to_cwd, to_path, offset, &data, last).await?;
        offset += data.len() as u64;
        if last {
            break;
        }
    }
    Ok(offset)
}

fn unexpected(answer: &Answer) -> Error {
    let _ = answer;
    Error::Failed(Failure::new(
        Code::Io,
        "unexpected answer kind for this request",
    ))
}

struct Remote {
    addr: String,
    psk: [u8; 32],
    conn: AsyncMutex<Option<Arc<Conn>>>,
}

impl Remote {
    async fn conn(&self) -> Result<Arc<Conn>, Error> {
        let mut guard = self.conn.lock().await;
        if let Some(conn) = guard.as_ref()
            && !conn.dead.load(Ordering::SeqCst)
        {
            return Ok(conn.clone());
        }
        let stream = transport::connect(&self.addr, &self.psk)
            .await
            .map_err(|e| Error::Unavailable(format!("cannot reach {}: {e}", self.addr)))?;
        let conn = Arc::new(Conn::start(stream, HANDSHAKE).await?);
        *guard = Some(conn.clone());
        Ok(conn)
    }

    async fn forget(&self) {
        *self.conn.lock().await = None;
    }
}

type Waiters = Arc<Mutex<HashMap<u64, oneshot::Sender<(Response, Vec<u8>)>>>>;

struct Conn {
    tx: mpsc::Sender<(Vec<u8>, Vec<u8>)>,
    pending: Waiters,
    next: AtomicU64,
    dead: Arc<AtomicBool>,
    greeting: Greeting,
    max_frame: usize,
}

impl Conn {
    async fn start<S>(stream: S, handshake: Duration) -> Result<Conn, Error>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut reader, mut writer) = tokio::io::split(stream);

        let frame = timeout(
            handshake,
            proto::read_frame(&mut reader, proto::MAX_HEADER + 4096),
        )
        .await
        .map_err(|_| Error::Unavailable("timed out waiting for the greeting".into()))?
        .map_err(|e| Error::Unavailable(format!("connection error during greeting: {e}")))?
        .ok_or_else(|| Error::Unavailable("connection closed before greeting".into()))?;

        let response: Response = serde_json::from_slice(&frame.header)
            .map_err(|e| Error::Unavailable(format!("bad greeting: {e}")))?;
        let greeting = match response.result {
            Reply::Ok(Answer::Hello {
                protocol,
                version,
                host,
                limits,
            }) => {
                if protocol != PROTOCOL {
                    return Err(Error::Unavailable(format!(
                        "protocol {protocol} != {PROTOCOL}; update the older side"
                    )));
                }
                Greeting {
                    protocol,
                    version,
                    host,
                    limits,
                }
            }
            _ => return Err(Error::Unavailable("first frame was not a greeting".into())),
        };
        let max_frame = greeting.limits.max_frame();

        let (tx, mut rx) = mpsc::channel::<(Vec<u8>, Vec<u8>)>(32);
        let pending: Waiters = Arc::new(Mutex::new(HashMap::new()));
        let dead = Arc::new(AtomicBool::new(false));

        {
            let dead = dead.clone();
            tokio::spawn(async move {
                while let Some((header, body)) = rx.recv().await {
                    if proto::write_frame(&mut writer, &header, &body)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                dead.store(true, Ordering::SeqCst);
            });
        }
        {
            let pending = pending.clone();
            let dead = dead.clone();
            tokio::spawn(async move {
                while let Ok(Some(frame)) = proto::read_frame(&mut reader, max_frame).await {
                    if let Ok(response) = serde_json::from_slice::<Response>(&frame.header) {
                        let waiter = pending.lock().unwrap().remove(&response.id);
                        if let Some(waiter) = waiter {
                            let _ = waiter.send((response, frame.body));
                        }
                    }
                }
                // A dropped connection wakes every waiter as Unavailable, never as
                // a failed operation.
                dead.store(true, Ordering::SeqCst);
                pending.lock().unwrap().clear();
            });
        }

        Ok(Conn {
            tx,
            pending,
            next: AtomicU64::new(1),
            dead,
            greeting,
            max_frame,
        })
    }

    async fn call(
        &self,
        cwd: Option<&str>,
        op: &Op,
        body: Vec<u8>,
        wait: Duration,
    ) -> Result<(Answer, Vec<u8>), Error> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(Error::Unavailable("the connection is down".into()));
        }
        if body.len() > self.max_frame {
            return Err(Error::Failed(Failure::new(
                Code::TooLarge,
                "body exceeds the frame limit",
            )));
        }

        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let request = Request {
            id,
            cwd: cwd.map(|s| s.to_owned()),
            op: op.clone(),
        };
        let header = serde_json::to_vec(&request).expect("request serializes");

        let (otx, orx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, otx);

        if self.tx.send((header, body)).await.is_err() {
            self.pending.lock().unwrap().remove(&id);
            return Err(Error::Unavailable("the connection is down".into()));
        }

        match timeout(wait, orx).await {
            Ok(Ok((response, body))) => match response.result {
                Reply::Ok(answer) => Ok((answer, body)),
                Reply::Err(failure) => Err(Error::Failed(failure)),
            },
            Ok(Err(_)) => Err(Error::Unavailable("the connection went down".into())),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(Error::Unavailable("timed out waiting for a reply".into()))
            }
        }
    }
}
