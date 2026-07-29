//! Проволочный формат: кадр, запрос, ответ, коды ошибок.
//!
//! Кадр — две длины, JSON-шапка и сырое тело. Содержимое файлов едет телом,
//! мимо JSON: base64 раздувает вчетверо и заставляет обе стороны держать в
//! памяти ещё одну копию, а гигабайтные архивы и без того на пределе.
//!
//! Шапка несёт `id`, и ответы приходят в любом порядке: по одному
//! соединению идут все операции разом, и долгая команда не должна запирать
//! чтение файла. Рабочий каталог — поле запроса, а не состояние сессии:
//! состояние на общем соединении — это гонка между чатами, у каждого из
//! которых свой каталог.

use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Версия протокола: клиент старше или младше демона — честный отказ на
/// рукопожатии, а не разъезжающиеся поля в середине разговора.
pub const PROTOCOL: u32 = 1;

/// Потолок JSON-шапки. Шапка — это метаданные операции; мегабайт хватает и
/// самому длинному пути, а всё, что больше, — мусор или чужой протокол.
pub const MAX_HEADER: usize = 1024 * 1024;

/// Кадр целиком: шапка и тело.
#[derive(Debug)]
pub struct Frame {
    pub header: Vec<u8>,
    pub body: Vec<u8>,
}

/// Запрос. `cwd` — от чего считать относительные пути и где исполнять
/// команду; без него относительный путь считается от каталога демона.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub op: Op,
}

/// Операция. Тело кадра несёт данные записи, образец поиска или stdin
/// команды — что именно, видно по операции.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Op {
    /// Живо ли соединение. Простаивающая ssh-труба умеет умирать молча.
    Ping,
    /// Метаданные пути: тип, размер, права, время правки.
    Stat { path: String },
    /// Содержимое каталога.
    List { path: String },
    /// Кусок файла: `len` не задан — до конца, в пределах потолка чтения.
    Read {
        path: String,
        #[serde(default)]
        offset: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        len: Option<u64>,
    },
    /// Файл целиком (тело кадра). Пишется атомарно.
    Write {
        path: String,
        #[serde(default)]
        create_dirs: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
    },
    /// Байты (тело кадра) поверх существующих; `truncate` обрубает хвост.
    WriteAt {
        path: String,
        offset: u64,
        #[serde(default)]
        truncate: bool,
    },
    /// Смещения вхождений образца (тело кадра). Файл читается потоком на
    /// той стороне — по проводу едут только находки.
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
    Rename { from: String, to: String },
    /// Команда через `sh -c` с таймаутом; тело кадра уезжает ей на вход.
    Exec { command: String, timeout_ms: u64 },
}

/// Ответ на запрос с тем же `id`. Рукопожатие приходит с `id` = 0 само,
/// без запроса.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    #[serde(flatten)]
    pub result: Reply,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reply {
    Ok(Answer),
    Err(Failure),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Answer {
    /// Первый кадр соединения: с кем и о чём мы говорим.
    Hello {
        protocol: u32,
        version: String,
        host: String,
        limits: crate::limits::Limits,
    },
    Pong,
    /// Операция без ответных данных: mkdir, remove, rename.
    Done,
    Stat { entry: Entry },
    List { entries: Vec<Entry>, stopped: bool },
    /// Байты — телом кадра; `total` — вся длина файла, чтобы спрашивающий
    /// видел, где он в файле и сколько осталось.
    Read { total: u64, offset: u64 },
    Wrote { total: u64 },
    /// `stopped` — упёрлись в `limit`, а не дочитали файл.
    Find {
        total: u64,
        offsets: Vec<u64>,
        stopped: bool,
    },
    /// `code` пуст, если команду убил сигнал.
    Exec {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    },
}

/// Запись каталога или сам путь у `stat`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    pub size: u64,
    /// Права в юниксовом смысле, младшие 12 бит.
    pub mode: u32,
    /// Время правки, unix-секунды; None — файловая система не сказала.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime: Option<i64>,
    /// Куда указывает симлинк.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

/// Отказ операции. Код нужен, чтобы спрашивающий отличал «файла нет» от
/// «слишком велик» и не выдавал пустоту за содержимое.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Failure {
    pub code: Code,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Code {
    NotFound,
    NotAFile,
    NotADir,
    /// Путь вне разрешённых корней или прав не хватило.
    Denied,
    TooLarge,
    Timeout,
    /// Запрос бессмысленный: пустой путь, пустой образец, нулевой лимит.
    Invalid,
    /// Операция выключена настройкой машины.
    Unsupported,
    Io,
}

impl Failure {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(Code::Invalid, message)
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

/// Записать кадр целиком одной порцией: соседний кадр из другой задачи не
/// должен вклиниться между шапкой и телом.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &[u8],
    body: &[u8],
) -> io::Result<()> {
    let mut frame = Vec::with_capacity(8 + header.len() + body.len());
    frame.extend_from_slice(&(header.len() as u32).to_be_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(header);
    frame.extend_from_slice(body);
    writer.write_all(&frame).await?;
    writer.flush().await
}

/// Прочитать кадр. `None` — собеседник закрылся на границе кадра (это не
/// ошибка); оборванный на середине кадр — ошибка, иначе обрезанная запись
/// выглядела бы как удачная.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_body: u64,
) -> io::Result<Option<Frame>> {
    let mut lengths = [0u8; 8];
    // первый байт отдельно: только на нём EOF означает «разговор окончен»
    match reader.read_exact(&mut lengths[..1]).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    reader.read_exact(&mut lengths[1..]).await?;

    let header_len = u32::from_be_bytes(lengths[..4].try_into().unwrap()) as usize;
    let body_len = u64::from(u32::from_be_bytes(lengths[4..].try_into().unwrap()));
    if header_len > MAX_HEADER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame header of {header_len} bytes exceeds the {MAX_HEADER} byte limit"),
        ));
    }
    if body_len > max_body {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame body of {body_len} bytes exceeds the {max_body} byte limit"),
        ));
    }
    let mut header = vec![0u8; header_len];
    reader.read_exact(&mut header).await?;
    let mut body = vec![0u8; body_len as usize];
    reader.read_exact(&mut body).await?;
    Ok(Some(Frame { header, body }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(value: &impl Serialize) -> Vec<u8> {
        serde_json::to_vec(value).unwrap()
    }

    #[tokio::test]
    async fn frame_round_trip_keeps_header_and_body_apart() {
        let request = Request {
            id: 7,
            cwd: Some("/srv/games".into()),
            op: Op::Write { path: "a.bin".into(), create_dirs: true, mode: None },
        };
        let mut wire = Vec::new();
        write_frame(&mut wire, &header(&request), b"\x00\xffbytes").await.unwrap();

        let frame = read_frame(&mut wire.as_slice(), 1024).await.unwrap().unwrap();
        let back: Request = serde_json::from_slice(&frame.header).unwrap();
        assert_eq!(back.id, 7);
        assert_eq!(back.cwd.as_deref(), Some("/srv/games"));
        // тело не тронуто: ни base64, ни экранирования
        assert_eq!(frame.body, b"\x00\xffbytes");
    }

    #[tokio::test]
    async fn clean_eof_ends_the_conversation_but_a_cut_frame_is_an_error() {
        let empty: &[u8] = &[];
        assert!(read_frame(&mut { empty }, 1024).await.unwrap().is_none());

        let mut wire = Vec::new();
        write_frame(&mut wire, b"{}", b"body").await.unwrap();
        wire.truncate(wire.len() - 2);
        let error = read_frame(&mut wire.as_slice(), 1024).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn oversized_body_is_refused_before_it_is_read() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"{}", &vec![0u8; 4096]).await.unwrap();
        let error = read_frame(&mut wire.as_slice(), 64).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("4096"), "{error}");
    }

    #[test]
    fn wire_shape_is_stable() {
        let response = Response {
            id: 3,
            result: Reply::Ok(Answer::Read { total: 900, offset: 16 }),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"id":3,"ok":{"kind":"read","total":900,"offset":16}}"#);

        let failed = Response {
            id: 4,
            result: Reply::Err(Failure::new(Code::NotFound, "gone")),
        };
        let json = serde_json::to_string(&failed).unwrap();
        assert_eq!(json, r#"{"id":4,"err":{"code":"not_found","message":"gone"}}"#);
        // и обратно: разбор своего же ответа не должен зависеть от порядка
        let back: Response = serde_json::from_str(&json).unwrap();
        assert!(matches!(back.result, Reply::Err(f) if f.code == Code::NotFound));
    }

    #[test]
    fn request_defaults_keep_short_headers_readable() {
        let request: Request =
            serde_json::from_str(r#"{"id":1,"op":{"kind":"read","path":"/etc/hosts"}}"#).unwrap();
        assert!(request.cwd.is_none());
        let Op::Read { offset, len, .. } = request.op else { panic!("read") };
        assert_eq!((offset, len), (0, None));
    }
}
