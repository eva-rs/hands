//! Настоящий бинарь через настоящий stdio — так его и запускает ssh.
//! Модульные тесты говорят с сервером по трубе в памяти и не увидели бы,
//! если бы демон, скажем, писал в stdout что-то помимо протокола.

use std::{process::Stdio, time::Duration};

use eva_hands::Hands;

async fn daemon() -> (Hands, tokio::process::Child) {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_eva-hands"))
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("the daemon starts");
    let reader = child.stdout.take().unwrap();
    let writer = child.stdin.take().unwrap();
    (Hands::over(reader, writer).await.expect("it greets us"), child)
}

#[tokio::test]
async fn the_daemon_talks_over_its_own_stdio() {
    let (hands, _child) = daemon().await;
    let greeting = hands.greeting().await.expect("a greeting");
    assert_eq!(greeting.protocol, eva_hands::proto::PROTOCOL);
    assert_eq!(greeting.version, env!("CARGO_PKG_VERSION"));

    let dir = std::env::temp_dir().join(format!("eva-hands-stdio-{}", std::process::id()));
    let path = dir.join("file.bin").to_string_lossy().into_owned();

    hands.write(None, &path, b"\x00\x01binary'quoted\n".to_vec(), true).await.unwrap();
    let (total, bytes) = hands.read(None, &path, 0, None).await.unwrap();
    assert_eq!((total as usize, bytes.as_slice()), (16, b"\x00\x01binary'quoted\n".as_slice()));

    // команда исполняется там же и в заданном каталоге
    let out = hands
        .exec(Some(&dir.to_string_lossy()), "pwd", Duration::from_secs(10), Vec::new())
        .await
        .unwrap();
    assert!(out.ok(), "{out:?}");
    assert_eq!(out.stdout.trim(), dir.to_string_lossy());

    let _ = std::fs::remove_dir_all(&dir);
}
