//! Демон. Основной запуск — `eva-hands serve` из ssh-сессии: разговор идёт
//! по stdin/stdout, и права даёт ssh-ключ, которым эту сессию открыли.
//!
//! Логи уходят в stderr и только туда: stdout занят протоколом.

use std::{path::PathBuf, sync::Arc};

use clap::{Parser, Subcommand};
use eva_hands::{Limits, ops::Ops, server};

/// Где демон ищет настройку, если ей не сказали иного. Ssh запускает его
/// голой командой, поэтому путь должен быть известен заранее.
const DEFAULT_CONFIG: &str = "/etc/eva-hands.toml";

#[derive(Parser)]
#[command(name = "eva-hands", version, about = "Eva's hands on this machine")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve one conversation over stdin/stdout — how SSH starts the daemon.
    Serve {
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
    },
    /// Serve on a unix socket, for a client on this same machine.
    Daemon {
        #[arg(long, value_name = "PATH")]
        listen: PathBuf,
        #[arg(long, value_name = "FILE")]
        config: Option<PathBuf>,
        /// Socket permissions, octal.
        #[arg(long, default_value = "0600")]
        mode: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .target(env_logger::Target::Stderr)
        .init();

    match Cli::parse().command {
        Command::Serve { config } => {
            let ops = Arc::new(Ops::new(limits(config.as_deref())?));
            server::serve(tokio::io::stdin(), tokio::io::stdout(), ops).await?;
        }
        Command::Daemon { listen, config, mode } => {
            let ops = Arc::new(Ops::new(limits(config.as_deref())?));
            let mode = u32::from_str_radix(mode.trim_start_matches("0o"), 8)
                .map_err(|_| format!("--mode {mode} is not an octal number"))?;
            daemon(&listen, mode, ops).await?;
        }
    }
    Ok(())
}

async fn daemon(
    listen: &std::path::Path,
    mode: u32,
    ops: Arc<Ops>,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    // сокет, оставшийся от прежнего запуска, занял бы путь и не дал
    // подняться — а слушать его всё равно уже некому
    if listen.exists() {
        std::fs::remove_file(listen)?;
    }
    if let Some(parent) = listen.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = tokio::net::UnixListener::bind(listen)?;
    std::fs::set_permissions(listen, PermissionsExt::from_mode(mode))?;
    log::info!("listening on {}", listen.display());

    loop {
        let (stream, _) = listener.accept().await?;
        let ops = ops.clone();
        tokio::spawn(async move {
            let (reader, writer) = stream.into_split();
            if let Err(error) = server::serve(reader, writer, ops).await {
                log::warn!("connection ended: {error}");
            }
        });
    }
}

/// Настройка машины: явный путь обязан существовать, путь по умолчанию —
/// нет. Молча работать с чужими потолками хуже, чем не подняться.
fn limits(config: Option<&std::path::Path>) -> Result<Limits, Box<dyn std::error::Error>> {
    let (path, required) = match config {
        Some(path) => (path, true),
        None => (std::path::Path::new(DEFAULT_CONFIG), false),
    };
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => {
            Ok(Limits::default())
        }
        Err(error) => Err(format!("{}: {error}", path.display()).into()),
    }
}
