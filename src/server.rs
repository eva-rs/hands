//! Сторона машины: читает кадры, исполняет операции, пишет ответы.
//!
//! Транспорт сюда приходит уже готовым — stdio ssh-сессии или юникс-сокет.
//! Запросы исполняются одновременно и отвечают в любом порядке: по одному
//! соединению идёт вся работа сразу, и минутная команда не должна запирать
//! чтение файла.

use std::sync::Arc;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Semaphore, mpsc},
};

use crate::{
    ops::Ops,
    proto::{self, Answer, Failure, Reply, Request, Response},
};

/// Сколько операций разом исполняем на одном соединении. Потолок не про
/// скорость, а про то, чтобы поток запросов не расплодил процессы.
const INFLIGHT: usize = 16;

/// Обслужить соединение до конца разговора.
pub async fn serve<R, W>(reader: R, writer: W, ops: Arc<Ops>) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (out, mut queue) = mpsc::channel::<(Vec<u8>, Vec<u8>)>(INFLIGHT * 2);
    let pump = tokio::spawn(async move {
        let mut writer = writer;
        while let Some((header, body)) = queue.recv().await {
            if proto::write_frame(&mut writer, &header, &body).await.is_err() {
                break;
            }
        }
    });

    // рукопожатие первым кадром: клиент по нему узнаёт и версию протокола,
    // и потолки машины — а если руки не установлены, он увидит не молчание,
    // а вопль ssh про ненайденную команду
    let hello = Answer::Hello {
        protocol: proto::PROTOCOL,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        host: hostname(),
        limits: ops.limits.clone(),
    };
    let _ = out.send((frame(0, Reply::Ok(hello)), Vec::new())).await;

    let inflight = Arc::new(Semaphore::new(INFLIGHT));
    let mut reader = reader;
    let max_body = ops.limits.max_frame();
    loop {
        let Some(incoming) = proto::read_frame(&mut reader, max_body).await? else {
            break;
        };
        let request: Request = match serde_json::from_slice(&incoming.header) {
            Ok(request) => request,
            Err(error) => {
                // id неизвестен — отвечаем нулевым: ответ повиснет без
                // адресата, но собеседник хотя бы увидит, что его не поняли
                let failure = Failure::invalid(format!("could not read the request: {error}"));
                let _ = out.send((frame(0, Reply::Err(failure)), Vec::new())).await;
                continue;
            }
        };
        let permit = inflight.clone().acquire_owned().await.expect("semaphore is open");
        let ops = ops.clone();
        let out = out.clone();
        tokio::spawn(async move {
            let id = request.id;
            let (reply, body) = match ops.run(request, incoming.body).await {
                Ok((answer, body)) => (Reply::Ok(answer), body),
                Err(failure) => (Reply::Err(failure), Vec::new()),
            };
            let _ = out.send((frame(id, reply), body)).await;
            drop(permit);
        });
    }

    drop(out);
    let _ = pump.await;
    Ok(())
}

fn frame(id: u64, result: Reply) -> Vec<u8> {
    serde_json::to_vec(&Response { id, result }).expect("a response is always serialisable")
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_owned())
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{limits::Limits, proto::Op};

    /// Сервер на памяти: кадры ходят по трубе, ssh не нужен.
    async fn pipe() -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
        let (mine, theirs) = tokio::io::duplex(64 * 1024);
        let (read, write) = tokio::io::split(theirs);
        let served = tokio::spawn(async move {
            let _ = serve(read, write, Arc::new(Ops::new(Limits::default()))).await;
        });
        (mine, served)
    }

    async fn ask(
        wire: &mut tokio::io::DuplexStream,
        request: &Request,
        body: &[u8],
    ) -> (Response, Vec<u8>) {
        let header = serde_json::to_vec(request).unwrap();
        proto::write_frame(wire, &header, body).await.unwrap();
        let frame = proto::read_frame(wire, 1 << 20).await.unwrap().unwrap();
        (serde_json::from_slice(&frame.header).unwrap(), frame.body)
    }

    #[tokio::test]
    async fn greets_first_then_answers() {
        let (mut wire, _served) = pipe().await;
        let frame = proto::read_frame(&mut wire, 1 << 20).await.unwrap().unwrap();
        let hello: Response = serde_json::from_slice(&frame.header).unwrap();
        assert_eq!(hello.id, 0);
        let Reply::Ok(Answer::Hello { protocol, .. }) = hello.result else { panic!("hello") };
        assert_eq!(protocol, proto::PROTOCOL);

        let request = Request { id: 5, cwd: None, op: Op::Ping };
        let (response, _) = ask(&mut wire, &request, b"").await;
        assert_eq!(response.id, 5);
        assert!(matches!(response.result, Reply::Ok(Answer::Pong)));
    }

    #[tokio::test]
    async fn a_broken_header_does_not_end_the_conversation() {
        let (mut wire, _served) = pipe().await;
        let _hello = proto::read_frame(&mut wire, 1 << 20).await.unwrap().unwrap();

        proto::write_frame(&mut wire, b"{not json}", b"").await.unwrap();
        let frame = proto::read_frame(&mut wire, 1 << 20).await.unwrap().unwrap();
        let response: Response = serde_json::from_slice(&frame.header).unwrap();
        assert!(matches!(response.result, Reply::Err(_)));

        // и следующая операция всё ещё обслуживается
        let request = Request { id: 9, cwd: None, op: Op::Ping };
        let (response, _) = ask(&mut wire, &request, b"").await;
        assert_eq!(response.id, 9);
    }

    #[tokio::test]
    async fn a_slow_command_does_not_block_the_next_request() {
        let (mut wire, _served) = pipe().await;
        let _hello = proto::read_frame(&mut wire, 1 << 20).await.unwrap().unwrap();

        let slow = Request {
            id: 1,
            cwd: None,
            op: Op::Exec { command: "sleep 1".into(), timeout_ms: 10_000 },
        };
        proto::write_frame(&mut wire, &serde_json::to_vec(&slow).unwrap(), b"").await.unwrap();
        // пинг уходит следом и обязан вернуться первым
        let (response, _) = ask(&mut wire, &Request { id: 2, cwd: None, op: Op::Ping }, b"").await;
        assert_eq!(response.id, 2);
    }
}
