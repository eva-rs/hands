//! Serving one connection: greet, then read requests and dispatch them to the
//! engine. Transport-agnostic — it runs over an [`EncryptedStream`] in the
//! daemon and over an in-memory duplex in tests.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc};

use crate::ops::{Ops, hostname};
use crate::proto::{self, Answer, Failure, PROTOCOL, Reply, Request, Response};

/// Cap on operations running at once, so a burst of requests can't spawn
/// unbounded work.
const INFLIGHT: usize = 16;

pub async fn serve<S>(stream: S, ops: Arc<Ops>) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, Vec<u8>)>(32);

    let writer_task = tokio::spawn(async move {
        while let Some((header, body)) = rx.recv().await {
            if proto::write_frame(&mut writer, &header, &body)
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let hello = Answer::Hello {
        protocol: PROTOCOL,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        host: hostname(),
        limits: ops.limits.clone(),
    };
    send(&tx, 0, Ok((hello, Vec::new()))).await;

    let sem = Arc::new(Semaphore::new(INFLIGHT));
    let max_frame = ops.limits.max_frame();

    loop {
        let frame = match proto::read_frame(&mut reader, max_frame).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(_) => break,
        };

        let request: Request = match serde_json::from_slice(&frame.header) {
            Ok(request) => request,
            // A broken header does not end the conversation.
            Err(e) => {
                send(
                    &tx,
                    0,
                    Err(Failure::invalid(format!("bad request header: {e}"))),
                )
                .await;
                continue;
            }
        };

        let permit = sem.clone().acquire_owned().await.unwrap();
        let ops = ops.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let id = request.id;
            let result = ops.run(request, frame.body).await;
            send(&tx, id, result).await;
            drop(permit);
        });
    }

    drop(tx);
    let _ = writer_task.await;
    Ok(())
}

async fn send(
    tx: &mpsc::Sender<(Vec<u8>, Vec<u8>)>,
    id: u64,
    result: Result<(Answer, Vec<u8>), Failure>,
) {
    let (reply, body) = match result {
        Ok((answer, body)) => (Reply::Ok(answer), body),
        Err(failure) => (Reply::Err(failure), Vec::new()),
    };
    let response = Response { id, result: reply };
    let header = serde_json::to_vec(&response).expect("response serializes");
    let _ = tx.send((header, body)).await;
}
