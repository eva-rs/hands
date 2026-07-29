//! Транспорт: свой ssh — и сервер, и клиент. Ssh-демона на машине не нужно,
//! ssh-бинаря у клиента тоже: руки слушают собственный порт и пускают только
//! того, кто владеет приватным ключом из своего `authorized_keys`.
//!
//! Криптография не наша: рукопожатие, обмен ключами, шифр и проверка
//! подписи — реализация протокола SSH (`russh`). Своего здесь ровно две
//! вещи: кого пускать и что течёт внутри канала — наши кадры.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use russh::{
    Channel, ChannelOpenFailure, ChannelStream, MethodKind, MethodSet, client,
    keys::{
        Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey, load_secret_key, ssh_key,
    },
    server::{self, Auth, Msg, Server as _, Session},
};
use tokio::{
    io::{ReadHalf, WriteHalf},
    net::TcpListener,
};

use crate::{client::Error, ops::Ops};

/// Как часто спрашиваем «жив ли ты» на простаивающем соединении. Ядро
/// держит его часами, а выброшенное NAT-ом соединение иначе обнаружится
/// только операцией.
const KEEPALIVE: Duration = Duration::from_secs(30);

/// Сколько неотвеченных keepalive терпим, прежде чем считать соединение
/// мёртвым.
const KEEPALIVE_MAX: usize = 3;

/// Пауза перед отказом в аутентификации — чтобы по времени ответа нельзя
/// было отличить неизвестный ключ от известного.
const REJECTION_DELAY: Duration = Duration::from_secs(2);

// --- сторона машины ---------------------------------------------------

/// Кому руки открываются. Формат тот же, что у `authorized_keys`: одна
/// строка — один публичный ключ.
pub struct Access {
    allowed: Vec<PublicKey>,
}

impl Access {
    /// Разобрать `authorized_keys`. Строки с опциями (`command="…"`,
    /// `from="…"`) не поддерживаются: это возможности ssh-демона, которого
    /// здесь нет, — что позволено рукам, говорит их собственная настройка.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut allowed = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match PublicKey::from_openssh(line) {
                Ok(key) => allowed.push(key),
                Err(error) => log::warn!("skipping an unreadable authorized key: {error}"),
            }
        }
        if allowed.is_empty() {
            return Err("no usable public keys: the hands would let nobody in".to_owned());
        }
        Ok(Self { allowed })
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Self::parse(&text).map_err(|why| format!("{}: {why}", path.display()))
    }

    /// Ключ сравнивается по самому ключу: комментарий в конце строки —
    /// подпись для человека, а не часть удостоверения.
    pub fn allows(&self, key: &PublicKey) -> bool {
        self.allowed.iter().any(|known| known.key_data() == key.key_data())
    }

    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }
}

/// Ключ самой машины: им она представляется, и по нему клиент узнаёт, что
/// пришёл туда же, куда в прошлый раз. Файла нет — заводим и кладём рядом.
pub fn host_key(path: &Path) -> Result<PrivateKey, String> {
    match load_secret_key(path, None) {
        Ok(key) => Ok(key),
        Err(_) if !path.exists() => {
            let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
                .map_err(|error| format!("could not make a host key: {error}"))?;
            write_host_key(path, &key)?;
            log::info!("made a host key at {}", path.display());
            Ok(key)
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

fn write_host_key(path: &Path, key: &PrivateKey) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    let text = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|error| format!("could not write the host key: {error}"))?;
    // 0600 при создании, а не после: между созданием и chmod ключ был бы
    // читаем кем угодно
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    std::io::Write::write_all(&mut file, text.as_bytes())
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// Отпечаток ключа — им машина называется в логах и в настройке клиента.
pub fn fingerprint(key: &PublicKey) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// Слушать до конца света. Соединения обслуживаются параллельно, каждое
/// своими кадрами.
pub async fn listen(
    listener: TcpListener,
    host: PrivateKey,
    access: Arc<Access>,
    ops: Arc<Ops>,
) -> std::io::Result<()> {
    let config = Arc::new(server::Config {
        keys: vec![host],
        // пароля и прочего у нас нет вовсе, и обещать их клиенту незачем
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        auth_rejection_time: REJECTION_DELAY,
        auth_rejection_time_initial: Some(Duration::ZERO),
        // соединение живёт часами и подолгу молчит: обрывать его по тишине
        // нельзя, а вот спрашивать «жив ли» — нужно
        inactivity_timeout: None,
        keepalive_interval: Some(KEEPALIVE),
        keepalive_max: KEEPALIVE_MAX,
        ..Default::default()
    });
    let mut gate = Gate { access, ops };
    gate.run_on_socket(config, &listener).await
}

#[derive(Clone)]
struct Gate {
    access: Arc<Access>,
    ops: Arc<Ops>,
}

impl server::Server for Gate {
    type Handler = Self;

    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        log::info!("session ended: {error}");
    }
}

impl server::Handler for Gate {
    type Error = russh::Error;

    /// Проба ключа до подписи: неизвестному отвечаем сразу, не заставляя
    /// его подписывать то, что всё равно не примут.
    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(if self.access.allows(key) { Auth::Accept } else { Auth::reject() })
    }

    /// Подпись проверена — владение ключом доказано. Имя пользователя
    /// значения не имеет: удостоверение здесь одно, и это ключ.
    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        if self.access.allows(key) {
            log::info!("{user} came in with {}", fingerprint(key));
            return Ok(Auth::Accept);
        }
        log::warn!("refused {user} with an unknown key {}", fingerprint(key));
        Ok(Auth::reject())
    }

    /// Канал открыт — внутри него сразу начинается наш разговор.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        let ops = self.ops.clone();
        tokio::spawn(async move {
            let (reader, writer) = tokio::io::split(channel.into_stream());
            if let Err(error) = crate::server::serve(reader, writer, ops).await {
                log::info!("conversation ended: {error}");
            }
        });
        Ok(())
    }

    /// Всё остальное, чем богат ssh, — проброс портов, псевдотерминал,
    /// запуск команд самим ssh — нам не нужно и не открывается.
    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host: &str,
        _port: u32,
        _originator: &str,
        _originator_port: u32,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }
}

// --- сторона ядра -----------------------------------------------------

/// Куда идти за руками.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// `host:port` демона.
    pub address: String,
    /// Имя пользователя протокола; удостоверение — ключ, не оно.
    pub user: String,
    /// Приватный ключ, которым представляемся.
    pub key: PathBuf,
    /// Ожидаемый публичный ключ машины (строка `ssh-ed25519 AAAA…`).
    /// Не задан — принимаем любой и говорим об этом в лог: тогда чужой,
    /// вставший на этот адрес, увидит содержимое файлов.
    pub host_key: Option<String>,
}

/// Открытый канал к рукам.
pub struct Link {
    pub(crate) reader: ReadHalf<ChannelStream<client::Msg>>,
    pub(crate) writer: WriteHalf<ChannelStream<client::Msg>>,
    /// Пока ручка сессии жива — живо соединение.
    pub(crate) session: client::Handle<Verifier>,
}

/// Соединиться и открыть канал. Всё, что здесь не удалось, — это
/// недоступность рук: спрашивающий вправе пойти другим путём.
pub async fn connect(endpoint: &Endpoint) -> Result<Link, Error> {
    let key = load_secret_key(&endpoint.key, None)
        .map_err(|error| Error::Unavailable(format!("{}: {error}", endpoint.key.display())))?;
    let expected = match &endpoint.host_key {
        Some(text) => Some(PublicKey::from_openssh(text.trim()).map_err(|error| {
            Error::Unavailable(format!("the pinned host key does not parse: {error}"))
        })?),
        None => None,
    };
    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        keepalive_interval: Some(KEEPALIVE),
        keepalive_max: KEEPALIVE_MAX,
        ..Default::default()
    });

    let mut session = client::connect(config, &*endpoint.address, Verifier { expected })
        .await
        .map_err(|error| Error::Unavailable(format!("{}: {error}", endpoint.address)))?;
    let hash: Option<HashAlg> = session
        .best_supported_rsa_hash()
        .await
        .map_err(|error| Error::Unavailable(format!("{}: {error}", endpoint.address)))?
        .flatten();
    let accepted = session
        .authenticate_publickey(&endpoint.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
        .await
        .map_err(|error| Error::Unavailable(format!("{}: {error}", endpoint.address)))?;
    if !accepted.success() {
        return Err(Error::Unavailable(format!(
            "{}: the machine did not accept the key — is it in its authorized_keys?",
            endpoint.address
        )));
    }
    let channel = session
        .channel_open_session()
        .await
        .map_err(|error| Error::Unavailable(format!("{}: {error}", endpoint.address)))?;
    let (reader, writer) = tokio::io::split(channel.into_stream());
    Ok(Link { reader, writer, session })
}

/// Проверка ключа машины на той стороне.
pub struct Verifier {
    expected: Option<PublicKey>,
}

impl client::Handler for Verifier {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        match &self.expected {
            Some(pinned) => Ok(pinned.key_data() == key.key_data()),
            None => {
                log::warn!(
                    "the machine's host key is not pinned; it introduced itself as {} — \
                     put that into the config to keep a stranger from taking its place",
                    fingerprint(key)
                );
                Ok(true)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn some_key() -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
    }

    #[test]
    fn access_reads_authorized_keys_and_ignores_the_comment() {
        let key = some_key();
        let line = key.public_key().to_openssh().unwrap();
        let access = Access::parse(&format!(
            "# руки Господина\n\n{line} nero@laptop\n"
        ))
        .unwrap();
        assert_eq!(access.len(), 1);
        // тот же ключ с другой подписью — тот же ключ
        assert!(access.allows(key.public_key()));
        assert!(!access.allows(some_key().public_key()));
    }

    #[test]
    fn access_without_a_single_key_refuses_to_exist() {
        // пустой список пустил бы всех или никого — и то и другое молча
        assert!(Access::parse("# только комментарий\n").is_err());
        assert!(Access::parse("ssh-ed25519 not-a-key").is_err());
    }

    #[test]
    fn a_host_key_is_made_once_and_then_reused() {
        let dir = std::env::temp_dir().join(format!("eva-hands-hostkey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("host_key");

        let made = host_key(&path).unwrap();
        let again = host_key(&path).unwrap();
        assert_eq!(made.public_key().key_data(), again.public_key().key_data());

        // ключ машины не должен быть читаем никем, кроме неё
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "ключ хоста лежит с правами {mode:o}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
