mod cli;
mod config;
mod config_watcher;
mod constants;
mod helper;
mod multi_map;
mod protocol;
mod transport;
mod db_config;

pub use cli::Cli;
use cli::KeypairType;
pub use config::Config;
pub use constants::UDP_BUFFER_SIZE;

use anyhow::Result;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info};
use tokio::time::{sleep, Duration};

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "client")]
use client::run_client;

#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
use server::run_server;

use crate::config_watcher::{ConfigChange, ConfigWatcherHandle};
use crate::db_config::DbConfigManager;

const DEFAULT_CURVE: KeypairType = KeypairType::X25519;

fn get_str_from_keypair_type(curve: KeypairType) -> &'static str {
    match curve {
        KeypairType::X25519 => "25519",
        KeypairType::X448 => "448",
    }
}

#[cfg(feature = "noise")]
fn genkey(curve: Option<KeypairType>) -> Result<()> {
    let curve = curve.unwrap_or(DEFAULT_CURVE);
    // .parse(): 尝试将这个字符串解析为 snowstorm 库内部定义的 NoiseParams（协议参数）类型。
    let builder = snowstorm::Builder::new(
        format!(
            "Noise_KK_{}_ChaChaPoly_BLAKE2s",
            get_str_from_keypair_type(curve)
        )
        .parse()?,
    );
    let keypair = builder.generate_keypair()?;

    println!("Private Key:\n{}\n", base64::encode(keypair.private));
    println!("Public Key:\n{}", base64::encode(keypair.public));
    Ok(())
}

#[cfg(not(feature = "noise"))]
fn genkey(curve: Option<KeypairType>) -> Result<()> {
    crate::helper::feature_not_compile("nosie")
}

pub async fn run(args: Cli, shutdown_rx: broadcast::Receiver<bool>) -> Result<()> {
    if args.genkey.is_some() {
        return genkey(args.genkey.unwrap());
    }

    // If we are asked to save config from file to database, do that and exit
    if args.db_config.is_some() && args.config_path.is_some() {
        let db_path = args.db_config.as_ref().unwrap();
        let config_path = args.config_path.as_ref().unwrap();

        // Load config from file
        let config = Config::from_file(config_path).await?;

        // Save to database
        let db_manager = DbConfigManager::new(db_path)?;
        db_manager.save_config(&args.db_config_name, &config)?;

        println!("Configuration saved to database: {}", db_path.display());
        return Ok(());
    }

    // Raise `nofile` limit on linux and mac
    // 提升当前进程可以打开的文件描述符（File Descriptor）数量限制。
    fdlimit::raise_fd_limit();

    // Determine configuration source: file or database
    let _config = if let Some(ref db_path) = args.db_config {
        // Load config from database
        let db_manager = DbConfigManager::new(db_path)?;
        db_manager.load_config(&args.db_config_name)?
            .ok_or_else(|| anyhow::anyhow!("Configuration '{}' not found in database", args.db_config_name))?
    } else {
        // Load config from file (original behavior)
        let config_path = args.config_path.as_ref().unwrap();
        Config::from_file(config_path).await?
    };

    // For database config, start hot reload monitoring
    if args.db_config.is_some() && args.config_path.is_none() {
        let db_path = args.db_config.as_ref().unwrap().clone();
        let config_name = args.db_config_name.clone();
        let mut shutdown_rx_clone = shutdown_rx.resubscribe();

        // Start database config hot reload task
        tokio::spawn(async move {
            let mut last_config_hash = String::new();

            loop {
                tokio::select! {
                    _ = shutdown_rx_clone.recv() => break,
                    _ = sleep(Duration::from_secs(30)) => {
                        // Check for database configuration changes
                        if let Ok(db_manager) = DbConfigManager::new(&db_path) {
                            if let Ok(Some(current_config)) = db_manager.load_config(&config_name) {
                                // Simple hash-based comparison
                                let current_hash = format!("{:?}", current_config);

                                if current_hash != last_config_hash {
                                    info!("Database configuration changed, logging change...");
                                    last_config_hash = current_hash;
                                    // This is where restart logic would go in a complete implementation
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    // Spawn a config watcher. The watcher will send an initial signal to start the instance with a config
    // We'll still use the file path for config watcher, but config will be from either file or database
    let config_path = args.config_path.as_ref().unwrap();
    let mut cfg_watcher = ConfigWatcherHandle::new(config_path, shutdown_rx).await?;

    // shutdown_tx owns the instance
    // shutdown_tx.subscribe() 派生出新的接收端
    let (shutdown_tx, _) = broadcast::channel(1);

    // (The join handle of the last instance, The service update channel sender)
    // 在 Rust 异步编程中用于追踪和管理一个 正在运行中 的后台任务实例
    // 实现“单例任务管理”或“新旧任务替换”
    let mut last_instance: Option<(tokio::task::JoinHandle<_>, mpsc::Sender<ConfigChange>)> = None;

    while let Some(e) = cfg_watcher.event_rx.recv().await {
        match e {
            ConfigChange::General(config) => {
                // 任务异步的句柄。通过它你可以监控任务是否结束、等待它结束，或者强制杀死（abort）该任务
                // 如果last_instance 是Some（即里面有数据），就执行大括号里的逻辑
                if let Some((i, _)) = last_instance {
                    info!("General configuration change detected. Restarting...");
                    shutdown_tx.send(true)?;
                    // 第一个?：等待JoinHandle本身的结果。如果任务因为恐慌（Panic）或者被强制中止而失败，这里会捕获JoinError。
                    // 第二个?：如果任务内部返回的Result类型，这层?用于提取任务实际执行结果中的错误。
                    i.await??;
                }

                debug!("{:?}", config);

                // 多生产者，单消费者
                let (service_update_tx, service_update_rx) = mpsc::channel(1024);

                last_instance = Some((
                    tokio::spawn(run_instance(
                        *config,
                        args.clone(),
                        shutdown_tx.subscribe(),
                        service_update_rx,
                    )),
                    service_update_tx,
                ));
            }
            ev => {
                info!("Service change detected. {:?}", ev);
                if let Some((_, service_update_tx)) = &last_instance {
                    let _ = service_update_tx.send(ev).await;
                }
            }
        }
    }

    let _ = shutdown_tx.send(true);

    Ok(())
}

async fn run_instance(
    config: Config,
    args: Cli,
    shutdown_rx: broadcast::Receiver<bool>,
    service_update: mpsc::Receiver<ConfigChange>,
) -> Result<()> {
    // If db_config is specified, also save to database
    if let Some(ref db_path) = args.db_config {
        // Save config to database when running with db_config
        let db_manager = DbConfigManager::new(db_path)?;
        db_manager.save_config(&args.db_config_name, &config)?;
    }

    match determine_run_mode(&config, &args) {
        RunMode::Undetermine => panic!("Cannot determine running as a server or a client"),
        RunMode::Client => {
            #[cfg(not(feature = "client"))]
            crate::helper::feature_not_compile("client");
            #[cfg(feature = "client")]
            run_client(config, shutdown_rx, service_update).await
        }
        RunMode::Server => {
            #[cfg(not(feature = "server"))]
            crate::helper::feature_not_compile("server");
            #[cfg(feature = "server")]
            run_server(config, shutdown_rx, service_update).await
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
enum RunMode {
    Server,
    Client,
    Undetermine,
}

fn determine_run_mode(config: &Config, args: &Cli) -> RunMode {
    use RunMode::*;
    if args.client && args.server {
        Undetermine
    } else if args.client {
        Client
    } else if args.server {
        Server
    } else if config.client.is_some() && config.server.is_none() {
        Client
    } else if config.server.is_some() && config.client.is_none() {
        Server
    } else {
        Undetermine
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_run_mode() {
        use config::*;
        use RunMode::*;

        struct T {
            cfg_s: bool,
            cfg_c: bool,
            arg_s: bool,
            arg_c: bool,
            run_mode: RunMode,
        }

        let tests = [
            T {
                cfg_s: false,
                cfg_c: false,
                arg_s: false,
                arg_c: false,
                run_mode: Undetermine,
            },
            T {
                cfg_s: true,
                cfg_c: false,
                arg_s: false,
                arg_c: false,
                run_mode: Server,
            },
            T {
                cfg_s: false,
                cfg_c: true,
                arg_s: false,
                arg_c: false,
                run_mode: Client,
            },
            T {
                cfg_s: true,
                cfg_c: true,
                arg_s: false,
                arg_c: false,
                run_mode: Undetermine,
            },
            T {
                cfg_s: true,
                cfg_c: true,
                arg_s: true,
                arg_c: false,
                run_mode: Server,
            },
            T {
                cfg_s: true,
                cfg_c: true,
                arg_s: false,
                arg_c: true,
                run_mode: Client,
            },
            T {
                cfg_s: true,
                cfg_c: true,
                arg_s: true,
                arg_c: true,
                run_mode: Undetermine,
            },
        ];

        for t in tests {
            let config = Config {
                server: match t.cfg_s {
                    true => Some(ServerConfig::default()),
                    false => None,
                },
                client: match t.cfg_c {
                    true => Some(ClientConfig::default()),
                    false => None,
                },
            };

            let args = Cli {
                config_path: Some(std::path::PathBuf::new()),
                server: t.arg_s,
                client: t.arg_c,
                ..Default::default()
            };

            assert_eq!(determine_run_mode(&config, &args), t.run_mode);
        }
    }
}
