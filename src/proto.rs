//! The wire protocol.
//!
//! A frame is two big-endian lengths, a JSON header, then a raw body:
//!
//! ```text
//! u32 header_len | u32 body_len | header (JSON) | body (raw bytes)
//! ```
//!
//! File contents ride in the body, outside the JSON, so they are not base64
//! inflated. Every request carries an `id`; replies may come back in any order,
//! because a single connection multiplexes everything — a slow `exec` must not
//! block a file read. The working directory is a per-request field, not session
//! state.

use eva::data;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::limits::Limits;

/// Wire version. A mismatch is caught at the handshake ([`Answer::Hello`]).
pub const PROTOCOL: u32 = 3;

/// Deadline a `fetch` falls back to when the request leaves `timeout_ms` at 0.
pub const FETCH_TIMEOUT_MS: u64 = 300_000;

/// Ceiling on the JSON header, independent of body limits.
pub const MAX_HEADER: usize = 1024 * 1024;

#[data]
pub struct Request {
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub op: Op,
}

#[data]
#[serde(tag = "kind")]
pub enum Op {
    Ping,
    Stat {
        path: String,
    },
    List {
        path: String,
    },
    Read {
        path: String,
        #[serde(default)]
        offset: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        len: Option<u64>,
    },
    /// Whole-file, atomic. Body holds the contents.
    Write {
        path: String,
        #[serde(default)]
        create_dirs: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
    },
    /// In-place write at an offset. Body holds the bytes.
    WriteAt {
        path: String,
        offset: u64,
        #[serde(default)]
        truncate: bool,
    },
    /// Download a URL straight to disk, streaming — the bytes never cross the
    /// wire. A `path` ending in `/` is a directory: the leaf name comes from
    /// `Content-Disposition`, else from the URL tail, and the reply says where
    /// the file landed.
    Fetch {
        url: String,
        path: String,
        /// Proxy (`socks5://`/`http://`) — the caller sets the policy; the hands
        /// have no network policy of their own.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proxy: Option<String>,
        /// Body ceiling; 0 — `limits.max_write`.
        #[serde(default)]
        max_bytes: u64,
        /// Whole-request deadline; 0 — [`FETCH_TIMEOUT_MS`].
        #[serde(default)]
        timeout_ms: u64,
    },
    /// Streaming byte search. Body holds the pattern; the reply lists offsets.
    Find {
        path: String,
        #[serde(default)]
        from: u64,
        limit: u64,
    },
    Mkdir {
        path: String,
        #[serde(default)]
        parents: bool,
    },
    Remove {
        path: String,
        #[serde(default)]
        recursive: bool,
    },
    Rename {
        from: String,
        to: String,
    },
    /// Run a command through `sh -c`. Body holds stdin.
    Exec {
        command: String,
        timeout_ms: u64,
    },
    /// Start a background session (`sh -c`) that outlives the request. Body holds
    /// initial stdin. Reply is [`Answer::Started`].
    ExecStart {
        command: String,
    },
    /// Long-poll a session: returns as soon as there is new output, the process
    /// exits, or `max_wait_ms` elapses. Reply is [`Answer::Chunk`], whose body is
    /// `u32 stdout_len (BE) | stdout | stderr`.
    ExecPoll {
        session: u64,
        max_wait_ms: u64,
    },
    /// Feed bytes (body) to a session's stdin.
    ExecInput {
        session: u64,
    },
    /// Terminate a session and its process tree.
    ExecKill {
        session: u64,
    },
}

impl Op {
    /// Read-only ops are safe to retry after a dropped connection; mutating ops
    /// are not (an interrupted channel must never rewrite a file twice).
    pub fn is_read_only(&self) -> bool {
        matches!(
            self,
            Op::Ping | Op::Stat { .. } | Op::List { .. } | Op::Read { .. } | Op::Find { .. }
        )
    }
}

#[data]
pub struct Response {
    pub id: u64,
    #[serde(flatten)]
    pub result: Reply,
}

#[data]
pub enum Reply {
    Ok(Answer),
    Err(Failure),
}

#[data]
#[serde(tag = "kind")]
pub enum Answer {
    /// Sent unsolicited with `id = 0` as the first frame of every connection.
    Hello {
        protocol: u32,
        version: String,
        host: String,
        limits: Limits,
    },
    Pong,
    Done,
    Stat {
        entry: Entry,
    },
    List {
        entries: Vec<Entry>,
        stopped: bool,
    },
    /// Bytes ride in the body; `total` is the file's full length.
    Read {
        total: u64,
        offset: u64,
    },
    Wrote {
        total: u64,
    },
    /// A download landed on disk. `path` is where it actually went (the caller
    /// may have named only the directory); `final_url` is after redirects, and
    /// `media_type` comes from `Content-Type`.
    Fetched {
        total: u64,
        path: String,
        final_url: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        media_type: Option<String>,
    },
    Find {
        total: u64,
        offsets: Vec<u64>,
        stopped: bool,
    },
    Exec {
        code: Option<i32>,
        signal: Option<String>,
        timed_out_ms: Option<u64>,
        stdout: String,
        stderr: String,
    },
    /// A session was started.
    Started {
        session: u64,
    },
    /// One poll's worth of a session's output; bytes ride in the body as
    /// `u32 stdout_len (BE) | stdout | stderr`. `alive` is false once the process
    /// has exited, and then `code` is its exit code (`None` if killed by signal).
    Chunk {
        alive: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        code: Option<i32>,
    },
}

#[data]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub size: u64,
    pub mode: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[data(copy)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

#[data(error, display("{code:?}: {message}"))]
pub struct Failure {
    pub code: Code,
    pub message: String,
}

#[data(copy)]
pub enum Code {
    NotFound,
    NotAFile,
    NotADir,
    Denied,
    TooLarge,
    Timeout,
    Invalid,
    Unsupported,
    Io,
}

impl Failure {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(Code::Invalid, message)
    }
}

pub struct Frame {
    pub header: Vec<u8>,
    pub body: Vec<u8>,
}

fn broken(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_owned())
}

/// Write one frame with a single `write_all`, so a concurrent task's frame
/// cannot interleave between the header and the body.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &[u8],
    body: &[u8],
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(8 + header.len() + body.len());
    buf.extend_from_slice(&(header.len() as u32).to_be_bytes());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(header);
    buf.extend_from_slice(body);
    writer.write_all(&buf).await?;
    writer.flush().await
}

/// Read one frame. `Ok(None)` is a clean end of the conversation (EOF exactly on
/// a frame boundary); EOF partway through a frame is an error. Enforces
/// [`MAX_HEADER`] and `max_body` before allocating.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_body: usize,
) -> std::io::Result<Option<Frame>> {
    let mut first = [0u8; 1];
    if reader.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let mut rest = [0u8; 7];
    reader.read_exact(&mut rest).await?;

    let header_len = u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]) as usize;
    let body_len = u32::from_be_bytes([rest[3], rest[4], rest[5], rest[6]]) as usize;

    if header_len > MAX_HEADER {
        return Err(broken("header too large"));
    }
    if body_len > max_body {
        return Err(broken("body too large"));
    }

    let mut header = vec![0u8; header_len];
    reader.read_exact(&mut header).await?;
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;

    Ok(Some(Frame { header, body }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_answer_wire_shape() {
        let response = Response {
            id: 3,
            result: Reply::Ok(Answer::Read {
                total: 900,
                offset: 16,
            }),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            json,
            r#"{"id":3,"ok":{"kind":"read","total":900,"offset":16}}"#
        );
    }

    #[test]
    fn failure_wire_shape() {
        let response = Response {
            id: 4,
            result: Reply::Err(Failure::new(Code::NotFound, "gone")),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            json,
            r#"{"id":4,"err":{"code":"not_found","message":"gone"}}"#
        );
    }

    #[test]
    fn request_round_trips() {
        let request = Request {
            id: 7,
            cwd: Some("/tmp".into()),
            op: Op::Write {
                path: "a.txt".into(),
                create_dirs: true,
                mode: None,
            },
        };
        let json = serde_json::to_vec(&request).unwrap();
        let back: Request = serde_json::from_slice(&json).unwrap();
        assert_eq!(request, back);
    }

    #[tokio::test]
    async fn frame_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let header = br#"{"id":1}"#.to_vec();
        let body = vec![0u8, 1, 2, 3, 255];
        write_frame(&mut a, &header, &body).await.unwrap();
        drop(a);
        let frame = read_frame(&mut b, 1024).await.unwrap().unwrap();
        assert_eq!(frame.header, header);
        assert_eq!(frame.body, body);
        assert!(read_frame(&mut b, 1024).await.unwrap().is_none());
    }
}
