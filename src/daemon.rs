use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use iroh::SecretKey;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{info, warn};

use crate::{
    config::Config,
    control::{self, DaemonCommand, ReloadAck, RpcError},
    identity,
    observability::RuntimeState,
    runtime,
};

#[derive(Clone)]
struct Generation {
    config: Config,
    secret_key: SecretKey,
}

struct PendingReload {
    previous: Generation,
    reply: oneshot::Sender<std::result::Result<ReloadAck, RpcError>>,
}

// iroh's UDP actor may release a fixed bind address shortly after Endpoint::close
// completes. Keep the control socket alive while giving that actor a bounded
// quiescence window before starting the replacement generation.
const RESTART_SETTLE_DELAY: Duration = Duration::from_secs(3);

impl Generation {
    async fn load(config_path: &Path) -> Result<Self> {
        let config = Config::load(config_path).await?;
        let secret_key = identity::load(&config.identity_file)?;
        config.validate_local_id(secret_key.public())?;
        Ok(Self { config, secret_key })
    }
}

pub async fn run(config_path: PathBuf, socket_path: PathBuf) -> Result<()> {
    let initial = Generation::load(&config_path)
        .await
        .context("failed loading initial daemon generation")?;
    let listener = control::bind(&socket_path).await?;
    let (command_tx, command_rx) = mpsc::channel(16);
    let (active_config_tx, active_config_rx) = watch::channel(initial.config.clone());
    let (runtime_state_tx, runtime_state_rx) = watch::channel::<Option<Arc<RuntimeState>>>(None);
    let events = Arc::new(control::EventLog::default());
    let mut supervisor = tokio::spawn(supervise(
        config_path,
        initial,
        active_config_tx,
        command_rx,
        runtime_state_tx,
        events.clone(),
    ));
    let mut control_server = tokio::spawn(control::serve(
        listener,
        socket_path.clone(),
        active_config_rx,
        command_tx.clone(),
        runtime_state_rx,
        events,
    ));

    let result = tokio::select! {
        result = &mut supervisor => {
            control_server.abort();
            flatten_task("daemon supervisor", result)
        }
        result = &mut control_server => {
            let control_error = match result {
                Ok(Ok(())) => anyhow!("control server stopped unexpectedly"),
                Ok(Err(error)) => error,
                Err(error) => error.into(),
            };
            let (reply, stopped) = oneshot::channel();
            let _ = command_tx.send(DaemonCommand::Stop { reply }).await;
            let _ = stopped.await;
            match supervisor.await {
                Ok(Ok(())) => Err(control_error),
                Ok(Err(error)) => Err(error.context(control_error.to_string())),
                Err(error) => Err(anyhow!("daemon supervisor task failed: {error}; {control_error}")),
            }
        }
    };
    match tokio::fs::remove_file(&socket_path).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            warn!(socket = %socket_path.display(), %error, "failed removing control socket")
        }
    }
    result
}

async fn supervise(
    config_path: PathBuf,
    mut current: Generation,
    active_config: watch::Sender<Config>,
    mut commands: mpsc::Receiver<DaemonCommand>,
    runtime_state: watch::Sender<Option<Arc<RuntimeState>>>,
    events: Arc<control::EventLog>,
) -> Result<()> {
    let mut generation = 1_u64;
    let mut pending_reload: Option<PendingReload> = None;
    loop {
        let starting_generation = generation + u64::from(pending_reload.is_some());
        let endpoint_id = current.secret_key.public();
        info!(generation = starting_generation, %endpoint_id, "starting data-plane generation");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let mut shutdown_tx = Some(shutdown_tx);
        let (ready_tx, ready_rx) = oneshot::channel();
        let config = current.config.clone();
        let secret_key = current.secret_key.clone();
        let mut runtime_task = tokio::spawn(runtime::run_with_shutdown_ready_and_state(
            config,
            secret_key,
            async move {
                shutdown_rx
                    .await
                    .context("daemon runtime shutdown channel closed")?;
                Ok(())
            },
            Some(ready_tx),
            Some(runtime_state.clone()),
        ));

        let startup = tokio::select! {
            ready = ready_rx => match ready {
                Ok(()) => Ok(()),
                Err(_) => Err(runtime_result("data plane startup", (&mut runtime_task).await)),
            },
            result = &mut runtime_task => Err(runtime_result("data plane startup", result)),
            signal = shutdown_signal() => {
                signal?;
                info!(generation = starting_generation, "daemon shutdown requested during startup");
                if let Some(shutdown) = shutdown_tx.take() {
                    let _ = shutdown.send(());
                }
                return flatten_task("data plane", runtime_task.await);
            }
        };
        if let Err(error) = startup {
            if let Some(pending) = pending_reload.take() {
                let _ = pending.reply.send(Err(RpcError {
                    code: "reload_failed".into(),
                    message: error.to_string(),
                }));
                warn!(%error, "new data-plane generation failed; restoring previous generation");
                current = pending.previous;
                tokio::time::sleep(RESTART_SETTLE_DELAY).await;
                continue;
            }
            return Err(error);
        }

        active_config.send_replace(current.config.clone());
        if let Some(pending) = pending_reload.take() {
            generation = generation.saturating_add(1);
            let _ = pending.reply.send(Ok(ReloadAck {
                generation,
                endpoint_id: current.secret_key.public().to_string(),
            }));
        }
        events
            .publish(
                "daemon.ready",
                None,
                serde_json::json!({
                    "generation": generation,
                    "endpoint_id": current.secret_key.public().to_string(),
                }),
            )
            .await;

        let next_extension_expiry = match crate::extensions::ExtensionState::load(
            &crate::extensions::state_path(&current.config.identity_file),
        )
        .await
        {
            Ok(state) => state.next_expiry(crate::extensions::now_unix()),
            Err(error) => {
                warn!(%error, "failed scheduling extension route leases");
                None
            }
        };
        let expiry_wait = async move {
            match next_extension_expiry {
                Some(expires) => {
                    let delay = expires
                        .saturating_sub(crate::extensions::now_unix())
                        .saturating_add(1);
                    tokio::time::sleep(Duration::from_secs(delay)).await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::pin!(expiry_wait);

        'active: loop {
            tokio::select! {
                result = &mut runtime_task => {
                    return Err(runtime_result("data plane", result));
                }
                signal = shutdown_signal() => {
                    signal?;
                    info!(generation, "daemon shutdown requested");
                    if let Some(shutdown) = shutdown_tx.take() {
                        let _ = shutdown.send(());
                    }
                    return flatten_task("data plane", runtime_task.await);
                }
                command = commands.recv() => {
                    match command {
                        Some(DaemonCommand::Reload { reply }) => {
                            let next = match Generation::load(&config_path).await {
                                Ok(next) => next,
                                Err(error) => {
                                    let _ = reply.send(Err(RpcError {
                                        code: "reload_rejected".into(),
                                        message: error.to_string(),
                                    }));
                                    continue 'active;
                                }
                            };
                            if let Some(shutdown) = shutdown_tx.take() {
                                let _ = shutdown.send(());
                            }
                            if let Err(error) = flatten_task("data plane", runtime_task.await) {
                                let _ = reply.send(Err(RpcError {
                                    code: "reload_failed".into(),
                                    message: error.to_string(),
                                }));
                                return Err(error);
                            }
                            let previous = current;
                            current = next;
                            pending_reload = Some(PendingReload { previous, reply });
                            tokio::time::sleep(RESTART_SETTLE_DELAY).await;
                            break 'active;
                        }
                        Some(DaemonCommand::Stop { reply }) => {
                            if let Some(shutdown) = shutdown_tx.take() {
                                let _ = shutdown.send(());
                            }
                            let result = flatten_task("data plane", runtime_task.await);
                            let _ = reply.send(());
                            return result;
                        }
                        None => {
                            if let Some(shutdown) = shutdown_tx.take() {
                                let _ = shutdown.send(());
                            }
                            flatten_task("data plane", runtime_task.await)?;
                            return Err(anyhow!("control command channel stopped"));
                        }
                    }
                }
                _ = &mut expiry_wait => {
                    let path = crate::extensions::state_path(&current.config.identity_file);
                    let state = match crate::extensions::ExtensionState::load(&path).await {
                        Ok(state) => state,
                        Err(error) => {
                            warn!(%error, "failed checking extension route leases");
                            continue 'active;
                        }
                    };
                    let Some((next, expired)) = state.expire(crate::extensions::now_unix()) else {
                        continue 'active;
                    };
                    if let Err(error) = next.write(&path) {
                        warn!(%error, "failed expiring extension route leases");
                        continue 'active;
                    }
                    for route in &expired {
                        events.publish(
                            "route.expired",
                            Some(format!("{}/{}", route.owner, route.name)),
                            serde_json::to_value(route).unwrap_or_default(),
                        ).await;
                    }
                    if let Some(shutdown) = shutdown_tx.take() {
                        let _ = shutdown.send(());
                    }
                    if let Err(error) = flatten_task("data plane", runtime_task.await) {
                        let _ = state.write(&path);
                        return Err(error.context("failed reloading after route expiry"));
                    }
                    match Generation::load(&config_path).await {
                        Ok(next_generation) => {
                            current = next_generation;
                            generation = generation.saturating_add(1);
                            tokio::time::sleep(RESTART_SETTLE_DELAY).await;
                            break 'active;
                        }
                        Err(error) => {
                            let _ = state.write(&path);
                            return Err(error.context("route expiry produced an invalid generation"));
                        }
                    }
                }
            }
        }
    }
}

fn runtime_result(
    phase: &str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> anyhow::Error {
    match result {
        Ok(Ok(())) => anyhow!("{phase} stopped unexpectedly"),
        Ok(Err(error)) => error,
        Err(error) => anyhow!("{phase} task failed: {error}"),
    }
}

fn flatten_task(
    name: &str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(result) => result,
        Err(error) => Err(anyhow!("{name} task failed: {error}")),
    }
}

async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed installing SIGTERM handler")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("failed waiting for SIGINT"),
        signal = terminate.recv() => {
            signal.context("SIGTERM handler stopped unexpectedly")?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::task::JoinHandle;

    #[test]
    fn task_result_is_flattened_without_losing_context() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(async {
            let task: JoinHandle<Result<()>> = tokio::spawn(async { Ok(()) });
            task.await
        });
        flatten_task("test", result).unwrap();
    }
}
