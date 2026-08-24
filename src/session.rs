//! Background exec sessions: a process that outlives the request. The kernel
//! keeps the rich bookkeeping (output capping, live snapshots, redaction, chunk
//! ids); here we only own the process and hand back its raw output, stdin, and
//! exit status.
//!
//! Sessions are a field of [`Ops`](crate::ops::Ops), so a single registry is
//! shared across every connection and the local backend — a session survives a
//! client reconnect, and an abandoned one is reaped for idleness.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Notify;

use crate::limits::Limits;
use crate::proto::{Code, Failure};

const MAX_SESSIONS: usize = 32;
const IDLE_KILL: Duration = Duration::from_secs(300);
const REAP_TICK: Duration = Duration::from_secs(15);
const FINISHED_LINGER: Duration = Duration::from_secs(600);
/// Soft cap on unread output per stream. The kernel long-polls continuously, so
/// little accumulates; if a burst overflows, the oldest bytes are dropped and
/// counted rather than growing without bound.
const STREAM_CAP: usize = 8 * 1024 * 1024;
/// After the process exits, wait at most this long for the pipe readers to drain
/// (grandchildren can hold an inherited pipe open forever).
const IO_DRAIN: Duration = Duration::from_secs(2);

#[derive(Default)]
pub struct Sessions {
    inner: Mutex<HashMap<u64, Arc<Session>>>,
    next: AtomicU64,
}

impl Sessions {
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    pub fn get(&self, id: u64) -> Option<Arc<Session>> {
        self.inner.lock().unwrap().get(&id).cloned()
    }

    fn remove(&self, id: u64) {
        self.inner.lock().unwrap().remove(&id);
    }

    pub fn start(
        self: &Arc<Self>,
        limits: &Limits,
        cwd: Option<&str>,
        command: &str,
        stdin: Vec<u8>,
    ) -> Result<u64, Failure> {
        if !limits.exec {
            return Err(Failure::new(Code::Unsupported, "exec is disabled"));
        }
        if command.trim().is_empty() {
            return Err(Failure::invalid("empty command"));
        }
        {
            let mut inner = self.inner.lock().unwrap();
            if inner.len() >= MAX_SESSIONS {
                inner.retain(|_, s| !s.exited());
            }
            if inner.len() >= MAX_SESSIONS {
                return Err(Failure::new(
                    Code::Unsupported,
                    format!("too many live sessions ({MAX_SESSIONS})"),
                ));
            }
        }

        let mut child = spawn_shell(command, cwd)
            .map_err(|e| Failure::new(Code::Io, format!("failed to spawn shell: {e}")))?;
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let child_stdin = child.stdin.take();

        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let session = Arc::new(Session {
            stdin: tokio::sync::Mutex::new(child_stdin),
            bufs: Mutex::new(Buffers::new()),
            notify: Notify::new(),
            kill: Notify::new(),
        });
        self.inner.lock().unwrap().insert(id, session.clone());

        if !stdin.is_empty() {
            let session = session.clone();
            tokio::spawn(async move {
                let _ = session.write_stdin(&stdin).await;
            });
        }

        tokio::spawn(waiter(child, stdout, stderr, session.clone()));
        tokio::spawn(reaper(id, session, self.clone()));

        Ok(id)
    }
}

struct Buffers {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    dropped: u64,
    /// `None` while alive; `Some(code)` once exited (`code` None if signalled).
    exit: Option<Option<i32>>,
    exited: bool,
    last_activity: Instant,
}

impl Buffers {
    fn new() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            dropped: 0,
            exit: None,
            exited: false,
            last_activity: Instant::now(),
        }
    }
}

pub struct Session {
    stdin: tokio::sync::Mutex<Option<ChildStdin>>,
    bufs: Mutex<Buffers>,
    notify: Notify,
    kill: Notify,
}

impl Session {
    pub fn exited(&self) -> bool {
        self.bufs.lock().unwrap().exited
    }

    pub async fn write_stdin(&self, data: &[u8]) -> Result<(), Failure> {
        let mut slot = self.stdin.lock().await;
        let Some(stdin) = slot.as_mut() else {
            return Err(Failure::new(
                Code::Invalid,
                "the session's stdin is closed: the process has exited",
            ));
        };
        stdin
            .write_all(data)
            .await
            .map_err(|e| Failure::new(Code::Io, format!("stdin write failed: {e}")))?;
        stdin
            .flush()
            .await
            .map_err(|e| Failure::new(Code::Io, format!("stdin flush failed: {e}")))?;
        self.bufs.lock().unwrap().last_activity = Instant::now();
        Ok(())
    }

    pub fn kill(&self) {
        self.kill.notify_one();
    }

    /// Long-poll: return as soon as there is new output, the process has exited,
    /// or `max_wait` elapses. Drains and clears the output buffers.
    pub async fn poll(&self, max_wait: Duration) -> (Vec<u8>, Vec<u8>, bool, Option<i32>) {
        let deadline = tokio::time::Instant::now() + max_wait;
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);

            {
                let mut b = self.bufs.lock().unwrap();
                b.last_activity = Instant::now();
                if !b.stdout.is_empty() || !b.stderr.is_empty() || b.exited {
                    return (
                        std::mem::take(&mut b.stdout),
                        std::mem::take(&mut b.stderr),
                        !b.exited,
                        b.exit.flatten(),
                    );
                }
            }

            if tokio::time::Instant::now() >= deadline {
                let mut b = self.bufs.lock().unwrap();
                return (
                    std::mem::take(&mut b.stdout),
                    std::mem::take(&mut b.stderr),
                    !b.exited,
                    b.exit.flatten(),
                );
            }

            tokio::select! {
                _ = &mut notified => {}
                _ = tokio::time::sleep_until(deadline) => {}
            }
        }
    }
}

fn spawn_shell(command: &str, cwd: Option<&str>) -> std::io::Result<Child> {
    let build = |program: &str| {
        let mut cmd = Command::new(program);
        cmd.arg("-c").arg(command);
        if let Some(cwd) = cwd {
            cmd.current_dir(crate::ops::expand_home(cwd));
        }
        crate::ops::harden(&mut cmd);
        #[cfg(unix)]
        cmd.process_group(0);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        cmd
    };
    match build("sh").spawn() {
        Ok(child) => Ok(child),
        Err(_) => build("/bin/sh").spawn(),
    }
}

async fn pump<R: AsyncRead + Unpin>(mut reader: R, session: Arc<Session>, is_err: bool) {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                {
                    let mut b = session.bufs.lock().unwrap();
                    let target = if is_err { &mut b.stderr } else { &mut b.stdout };
                    target.extend_from_slice(&buf[..n]);
                    if target.len() > STREAM_CAP {
                        let over = target.len() - STREAM_CAP;
                        target.drain(..over);
                        b.dropped += over as u64;
                    }
                }
                session.notify.notify_one();
            }
        }
    }
}

async fn waiter<O, E>(mut child: Child, stdout: O, stderr: E, session: Arc<Session>)
where
    O: AsyncRead + Unpin + Send + 'static,
    E: AsyncRead + Unpin + Send + 'static,
{
    let h_out = tokio::spawn(pump(stdout, session.clone(), false));
    let h_err = tokio::spawn(pump(stderr, session.clone(), true));

    let status = tokio::select! {
        _ = session.kill.notified() => {
            kill_tree(child.id()).await;
            let _ = child.start_kill();
            child.wait().await.ok()
        }
        status = child.wait() => status.ok(),
    };

    // Drain the pipe readers, but don't hang on grandchildren holding the pipe.
    let drain = async {
        let _ = h_out.await;
        let _ = h_err.await;
    };
    if tokio::time::timeout(IO_DRAIN, drain).await.is_err() {
        // Readers time out only if the pipe is still held; the tasks are then
        // detached and the process is already gone.
    }

    {
        let mut b = session.bufs.lock().unwrap();
        b.exit = Some(status.and_then(|s| s.code()));
        b.exited = true;
    }
    *session.stdin.lock().await = None;
    session.notify.notify_one();
}

async fn reaper(id: u64, session: Arc<Session>, registry: Arc<Sessions>) {
    let mut finished_at: Option<Instant> = None;
    loop {
        tokio::time::sleep(REAP_TICK).await;
        let (idle, exited) = {
            let b = session.bufs.lock().unwrap();
            (b.last_activity.elapsed(), b.exited)
        };
        if exited {
            let since = finished_at.get_or_insert_with(Instant::now);
            if since.elapsed() >= FINISHED_LINGER {
                registry.remove(id);
                return;
            }
        } else if idle >= IDLE_KILL {
            log::info!(session = id; "exec session idle, killing");
            session.kill();
        }
    }
}

/// Kill the whole process group (`sh` plus its child). The group exists because
/// the session is spawned with `process_group(0)`.
async fn kill_tree(pid: Option<u32>) {
    if let Some(pid) = pid {
        let _ = Command::new("kill")
            .arg("-9")
            .arg("--")
            .arg(format!("-{pid}"))
            .output()
            .await;
    }
}
