//! The daemon: an eva service that listens for encrypted connections and serves
//! each one, plus a `keygen` helper for producing a pre-shared key.

use std::sync::Arc;

use eva::cli::{App, NoArgs};
use eva::component_configs::{ComponentConfig, ComponentConfigs};
use eva::supervisor::{Command, SlaveRx, Supervisor};
use eyre::Context;
use tokio::net::TcpListener;

use eva_hands::{Limits, Ops, Psk, server, transport};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct HandsConfig {
    #[serde(default = "default_listen")]
    listen: String,
    /// The pre-shared key. Keep it out of world-readable config — pass it via an
    /// environment file (`EVA_HANDS__KEY`) or a secret config file.
    key: Psk,
    #[serde(flatten)]
    limits: Limits,
}

fn default_listen() -> String {
    "0.0.0.0:2222".to_owned()
}

fn main() -> eyre::Result<()> {
    // `keygen` produces a key and exits — it must not require a config or a key,
    // so it runs before the config-loading App.
    if std::env::args().skip(1).any(|a| a == "keygen") {
        return keygen();
    }

    App::default()
        .env_prefix("EVA_")
        .require::<HandsConfig>("hands")
        .run(serve)
}

async fn serve(_: NoArgs, configs: ComponentConfigs) -> eyre::Result<()> {
    Supervisor::new(configs)
        .add::<HandsConfig>(listen)
        .wait_for_completion()
        .await
}

async fn listen(cfg: ComponentConfig<HandsConfig>, mut rx: SlaveRx) -> eyre::Result<()> {
    let psk = cfg.key.derive32();
    let ops = Arc::new(Ops::new(cfg.limits.clone()));

    let listener = TcpListener::bind(cfg.listen.as_str())
        .await
        .wrap_err_with(|| format!("failed to bind {}", cfg.listen))?;
    log::info!(listen = cfg.listen; "hands are up");

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        log::warn!(error:% = e; "accept failed");
                        continue;
                    }
                };
                tcp.set_nodelay(true).ok();
                let ops = ops.clone();
                tokio::spawn(async move {
                    match transport::responder_handshake(tcp, &psk).await {
                        Ok(stream) => {
                            if let Err(e) = server::serve(stream, ops).await {
                                log::debug!(error:% = e, peer:% = peer; "connection ended");
                            }
                        }
                        // Wrong key, or a malformed handshake — no channel opens.
                        Err(e) => log::debug!(error:% = e, peer:% = peer; "handshake rejected"),
                    }
                });
            }
            command = rx.recv() => match command {
                Some(Command::Shutdown) | None => {
                    log::info!("shutting down, no longer accepting connections");
                    return Ok(());
                }
            },
        }
    }
}

fn keygen() -> eyre::Result<()> {
    use base64::Engine;
    use eva::rand::RngCore;

    let mut key = [0u8; 32];
    eva::rand::rng().fill_bytes(&mut key);
    println!("{}", base64::engine::general_purpose::STANDARD.encode(key));
    Ok(())
}
