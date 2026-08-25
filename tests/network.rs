use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use eva_hands::client::FetchRequest;
use eva_hands::{Hands, Limits, Ops, Psk, copy, server, transport};
use tokio::net::TcpListener;

fn temp_dir() -> std::path::PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("eva-hands-net-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run a daemon on an ephemeral port. Returns its address.
async fn daemon(psk: &Psk) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let key = psk.derive32();
    let ops = Arc::new(Ops::new(Limits::default()));
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let ops = ops.clone();
            tokio::spawn(async move {
                if let Ok(stream) = transport::responder_handshake(tcp, &key).await {
                    let _ = server::serve(stream, ops).await;
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn local_mode_full_cycle() {
    let dir = temp_dir();
    let path = dir.join("f.bin").to_string_lossy().into_owned();
    let hands = Hands::local(Limits::default());

    let data = vec![42u8; 4096];
    hands.write(None, &path, &data, false, None).await.unwrap();
    let (total, got) = hands.read(None, &path, 0, None).await.unwrap();
    assert_eq!(total, 4096);
    assert_eq!(got, data);

    let out = hands
        .exec(None, "printf hi", 5000, Vec::new())
        .await
        .unwrap();
    assert!(out.ok());
    assert_eq!(out.stdout, "hi");

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn encrypted_roundtrip_and_greeting() {
    let psk = Psk::new("correct horse battery staple, but high entropy please");
    let addr = daemon(&psk).await;
    let dir = temp_dir();
    let path = dir.join("blob").to_string_lossy().into_owned();

    let hands = Hands::remote(addr, &psk);
    let greeting = hands.greeting().await.unwrap();
    assert_eq!(greeting.protocol, eva_hands::proto::PROTOCOL);

    // Binary content survives the channel intact.
    let data: Vec<u8> = (0..=255u8).cycle().take(9000).collect();
    let wrote = hands.write(None, &path, &data, false, None).await.unwrap();
    assert_eq!(wrote, 9000);
    let (total, got) = hands.read(None, &path, 0, None).await.unwrap();
    assert_eq!(total, 9000);
    assert_eq!(got, data);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn wrong_key_cannot_connect() {
    let psk = Psk::new("the-real-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    let addr = daemon(&psk).await;

    let hands = Hands::remote(addr, &Psk::new("a-different-key-bbbbbbbbbbbbbbbbbbbbbbbbbb"));
    let err = hands.ping(None).await.unwrap_err();
    assert!(err.is_unavailable(), "expected Unavailable, got {err:?}");
}

#[tokio::test]
async fn copy_local_to_remote_and_back() {
    let psk = Psk::new("transfer-key-high-entropy-xxxxxxxxxxxxxxxx");
    let addr = daemon(&psk).await;
    let remote = Hands::remote(addr, &psk);
    let local = Hands::local(Limits::default());

    let dir = temp_dir();
    let src = dir.join("src").to_string_lossy().into_owned();
    let on_remote = dir.join("remote_copy").to_string_lossy().into_owned();
    let back = dir.join("back").to_string_lossy().into_owned();

    // A file larger than one copy window (1 MiB) to exercise chunking.
    let data: Vec<u8> = (0..3_000_000u32).map(|i| i as u8).collect();
    local.write(None, &src, &data, false, None).await.unwrap();

    let n = copy(&local, None, &src, &remote, None, &on_remote).await.unwrap();
    assert_eq!(n, data.len() as u64);

    let n = copy(&remote, None, &on_remote, &local, None, &back).await.unwrap();
    assert_eq!(n, data.len() as u64);

    assert_eq!(std::fs::read(&back).unwrap(), data);
    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn session_local_stream_input_and_kill() {
    let hands = Hands::local(Limits::default());
    // Echoes each stdin line back, staying alive between lines.
    let sid = hands
        .exec_start(None, "while read line; do echo \"got:$line\"; done", Vec::new())
        .await
        .unwrap();
    hands.exec_input(sid, b"hello\n".to_vec()).await.unwrap();

    let mut seen = Vec::new();
    for _ in 0..40 {
        let (out, _err, alive, _code) = hands.exec_poll(sid, 300).await.unwrap();
        seen.extend_from_slice(&out);
        if String::from_utf8_lossy(&seen).contains("got:hello") {
            break;
        }
        assert!(alive, "process died before echoing");
    }
    assert!(String::from_utf8_lossy(&seen).contains("got:hello"), "{seen:?}");

    hands.exec_kill(sid).await.unwrap();
    let mut died = false;
    for _ in 0..40 {
        let (_o, _e, alive, _c) = hands.exec_poll(sid, 300).await.unwrap();
        if !alive {
            died = true;
            break;
        }
    }
    assert!(died, "session did not die after kill");
}

#[tokio::test]
async fn session_reports_exit_code() {
    let hands = Hands::local(Limits::default());
    let sid = hands
        .exec_start(None, "printf out; exit 3", Vec::new())
        .await
        .unwrap();
    let mut out = Vec::new();
    let mut code = None;
    for _ in 0..40 {
        let (o, _e, alive, c) = hands.exec_poll(sid, 300).await.unwrap();
        out.extend_from_slice(&o);
        if !alive {
            code = c;
            break;
        }
    }
    assert_eq!(code, Some(3));
    assert!(String::from_utf8_lossy(&out).contains("out"));
}

#[tokio::test]
async fn session_over_encrypted_channel() {
    let psk = Psk::new("session-key-high-entropy-zzzzzzzzzzzzzzzz");
    let addr = daemon(&psk).await;
    let hands = Hands::remote(addr, &psk);

    let sid = hands
        .exec_start(None, "printf hello; exit 0", Vec::new())
        .await
        .unwrap();
    let mut out = Vec::new();
    let mut code = None;
    for _ in 0..40 {
        let (o, _e, alive, c) = hands.exec_poll(sid, 300).await.unwrap();
        out.extend_from_slice(&o);
        if !alive {
            code = c;
            break;
        }
    }
    assert_eq!(code, Some(0));
    assert_eq!(String::from_utf8_lossy(&out).trim(), "hello");
}

#[tokio::test]
async fn multiplex_slow_exec_does_not_block_ping() {
    let psk = Psk::new("multiplex-key-high-entropy-yyyyyyyyyyyyyyyy");
    let addr = daemon(&psk).await;
    let hands = Arc::new(Hands::remote(addr, &psk));

    let slow = {
        let hands = hands.clone();
        tokio::spawn(async move { hands.exec(None, "sleep 1", 5000, Vec::new()).await })
    };

    // The ping must come back well before the slow exec finishes.
    let pinged = tokio::time::timeout(Duration::from_millis(400), hands.ping(None)).await;
    assert!(pinged.is_ok(), "ping was blocked by the slow exec");
    pinged.unwrap().unwrap();

    let out = slow.await.unwrap().unwrap();
    assert!(out.ok());
}

/// A download crosses no wire: only the request and the verdict do, so the
/// file appears on the machine even though the channel never carried it.
#[tokio::test]
async fn fetch_over_the_channel() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 4096];
        let _ = stream.read(&mut request).await;
        let _ = stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 7\r\n\
                  Content-Type: text/plain\r\n\r\nfetched",
            )
            .await;
        let _ = stream.shutdown().await;
    });

    let psk = Psk::new("correct horse battery staple, but high entropy please");
    let addr = daemon(&psk).await;
    let dir = temp_dir();
    let hands = Hands::remote(addr, &psk);

    let fetched = hands
        .fetch(
            None,
            FetchRequest {
                url: format!("http://{origin}/note.txt"),
                path: format!("{}/", dir.to_string_lossy()),
                proxy: None,
                max_bytes: 0,
                timeout_ms: 10_000,
            },
        )
        .await
        .unwrap();

    assert_eq!(fetched.total, 7);
    assert_eq!(fetched.media_type.as_deref(), Some("text/plain"));
    assert_eq!(fetched.path, dir.join("note.txt").to_string_lossy());
    assert_eq!(std::fs::read(&fetched.path).unwrap(), b"fetched");

    std::fs::remove_dir_all(&dir).ok();
}
