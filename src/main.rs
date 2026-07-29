//! Демон: слушает свой порт и пускает того, кто владеет приватным ключом
//! из его `authorized_keys`. Ssh-демон машины при этом ни при чём — руки
//! говорят своим протоколом внутри собственного ssh-канала.

use std::{path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand};
use eva_hands::{Limits, ops::Ops, transport};
use serde::Deserialize;

/// Где демон ищет настройку, если ей не сказали иного.
const DEFAULT_CONFIG: &str = "/etc/eva-hands.toml";

#[derive(Parser)]
#[command(name = "eva-hands", version, about = "Eva's hands on this machine")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Listen for the kernel and serve it.
    Serve {
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Override the listen address from the config.
        #[arg(long, value_name = "ADDR")]
        listen: Option<String>,
    },
    /// Print this machine's public host key — pin it in the client config.
    HostKey {
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
}

/// Настройка демона: чем слушать, кого пускать и сколько отдавать.
#[derive(Debug, Deserialize)]
#[serde(default)]
struct Config {
    listen: String,
    /// Ключ, которым машина представляется. Нет файла — заведётся сам.
    host_key: PathBuf,
    /// Публичные ключи тех, кому руки открываются.
    authorized_keys: PathBuf,
    #[serde(flatten)]
    limits: Limits,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:2222".to_owned(),
            host_key: "/var/lib/eva-hands/host_key".into(),
            authorized_keys: "/var/lib/eva-hands/authorized_keys".into(),
            limits: Limits::default(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();

    match Cli::parse().command {
        Command::Serve { config, listen } => {
            let mut config = load(config.as_deref())?;
            if let Some(address) = listen {
                config.listen = address;
            }
            serve(config).await?;
        }
        Command::HostKey { config } => {
            let config = load(config.as_deref())?;
            let key = transport::host_key(&config.host_key)?;
            let public = key.public_key();
            println!("{}", public.to_openssh()?);
            eprintln!("fingerprint: {}", transport::fingerprint(public));
        }
    }
    Ok(())
}

async fn serve(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    // ключи читаем до того, как открыть порт: слушать, никого не пуская, —
    // худший вид работоспособности
    let access = Arc::new(transport::Access::read(&config.authorized_keys)?);
    let host = transport::host_key(&config.host_key)?;
    let listener = tokio::net::TcpListener::bind(&config.listen).await?;

    log::info!(
        "listening on {} as {}, {} key(s) allowed in",
        config.listen,
        transport::fingerprint(host.public_key()),
        access.len()
    );
    transport::listen(listener, host, access, Arc::new(Ops::new(config.limits))).await?;
    Ok(())
}

/// Явный путь обязан существовать, путь по умолчанию — нет. Молча работать
/// с чужими потолками хуже, чем не подняться.
fn load(config: Option<&std::path::Path>) -> Result<Config, Box<dyn std::error::Error>> {
    let (path, required) = match config {
        Some(path) => (path, true),
        None => (std::path::Path::new(DEFAULT_CONFIG), false),
    };
    match std::fs::read_to_string(path) {
        Ok(text) => {
            Ok(toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => {
            Ok(Config::default())
        }
        Err(error) => Err(format!("{}: {error}", path.display()).into()),
    }
}
