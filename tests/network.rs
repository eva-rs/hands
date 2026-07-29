//! Руки целиком: демон слушает настоящий порт, клиент приходит по сети со
//! своим ключом. Модульные тесты говорят по трубе в памяти и не увидели бы
//! ни аутентификации, ни проверки ключа машины.

use std::{sync::Arc, time::Duration};

use eva_hands::{Endpoint, Hands, Limits, ops::Ops, transport};

struct Machine {
    address: String,
    /// Публичный ключ машины — его пинует клиент.
    host_key: String,
    dir: std::path::PathBuf,
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Поднять демон на свободном порту, пустив в него ровно эти ключи.
async fn machine(name: &str, allowed: &[String]) -> Machine {
    let dir = std::env::temp_dir().join(format!("eva-hands-net-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let host = transport::host_key(&dir.join("host_key")).unwrap();
    let host_key = host.public_key().to_openssh().unwrap();
    let access = Arc::new(transport::Access::parse(&allowed.join("\n")).unwrap());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let ops = Arc::new(Ops::new(Limits::default()));
    tokio::spawn(async move {
        let _ = transport::listen(listener, host, access, ops).await;
    });
    Machine { address, host_key, dir }
}

/// Завести ключ на диске и вернуть путь и его публичную половину.
fn key(dir: &std::path::Path, name: &str) -> (std::path::PathBuf, String) {
    let path = dir.join(name);
    let key = transport::host_key(&path).unwrap();
    (path, key.public_key().to_openssh().unwrap())
}

#[tokio::test]
async fn the_key_is_the_whole_permission() {
    let keys = std::env::temp_dir().join(format!("eva-hands-keys-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&keys);
    std::fs::create_dir_all(&keys).unwrap();
    let (mine, my_public) = key(&keys, "mine");
    let (stranger, _) = key(&keys, "stranger");

    let machine = machine("auth", &[my_public]).await;

    // свой ключ: руки открываются и работают
    let hands = Hands::remote(Endpoint {
        address: machine.address.clone(),
        user: "eva".into(),
        key: mine,
        host_key: Some(machine.host_key.clone()),
    });
    let greeting = hands.greeting().await.expect("рукопожатие");
    assert_eq!(greeting.protocol, eva_hands::proto::PROTOCOL);

    let path = machine.dir.join("file.bin").to_string_lossy().into_owned();
    hands.write(None, &path, b"\x00\x01binary'quoted\n".to_vec(), true).await.unwrap();
    let (total, bytes) = hands.read(None, &path, 0, None).await.unwrap();
    assert_eq!((total as usize, bytes.as_slice()), (16, b"\x00\x01binary'quoted\n".as_slice()));

    // чужой ключ: до операций дело не доходит
    let outsider = Hands::remote(Endpoint {
        address: machine.address.clone(),
        user: "eva".into(),
        key: stranger,
        host_key: Some(machine.host_key.clone()),
    });
    let error = outsider.stat(None, &path).await.unwrap_err();
    assert!(error.is_unavailable(), "{error}");
    assert!(error.to_string().contains("did not accept the key"), "{error}");

    let _ = std::fs::remove_dir_all(&keys);
}

#[tokio::test]
async fn a_machine_with_the_wrong_host_key_is_refused() {
    let keys = std::env::temp_dir().join(format!("eva-hands-hostpin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&keys);
    std::fs::create_dir_all(&keys).unwrap();
    let (mine, my_public) = key(&keys, "mine");
    let (_, someone_else) = key(&keys, "other");

    let machine = machine("hostpin", &[my_public]).await;
    // адрес тот, ключ машины — чужой: так выглядит подмена
    let hands = Hands::remote(Endpoint {
        address: machine.address.clone(),
        user: "eva".into(),
        key: mine,
        host_key: Some(someone_else),
    });
    let error = hands.ping().await.unwrap_err();
    assert!(error.is_unavailable(), "{error}");

    let _ = std::fs::remove_dir_all(&keys);
}

#[tokio::test]
async fn the_connection_carries_everything_at_once() {
    let keys = std::env::temp_dir().join(format!("eva-hands-mux-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&keys);
    std::fs::create_dir_all(&keys).unwrap();
    let (mine, my_public) = key(&keys, "mine");
    let machine = machine("mux", &[my_public]).await;

    let hands = Arc::new(Hands::remote(Endpoint {
        address: machine.address.clone(),
        user: "eva".into(),
        key: mine,
        host_key: Some(machine.host_key.clone()),
    }));
    let slow = {
        let hands = hands.clone();
        tokio::spawn(async move {
            hands.exec(None, "sleep 1; echo late", Duration::from_secs(10), Vec::new()).await
        })
    };
    // одно соединение, а долгая команда не запирает файловые операции
    hands.ping().await.unwrap();
    let dir = machine.dir.to_string_lossy().into_owned();
    assert!(!hands.list(None, &dir).await.unwrap().0.is_empty());
    assert_eq!(slow.await.unwrap().unwrap().stdout.trim(), "late");

    let _ = std::fs::remove_dir_all(&keys);
}
