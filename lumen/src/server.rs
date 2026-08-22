use std::{
    borrow::Cow, collections::HashMap, mem::discriminant, process::exit, sync::Arc, time::Instant,
};

use common::{
    async_drop::AsyncDropper,
    config::Config,
    db::Database,
    make_pretty_hex, md,
    metrics::LuminaVersion,
    rpc::{self, Error, HelloResult, RpcFail, RpcHello, RpcMessage},
    SharedState, SharedState_,
};
use native_tls::Identity;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use tracing::{debug, error, info, info_span, trace, warn, Instrument};

use crate::web;

async fn handle_transaction<'a, S: AsyncRead + AsyncWrite + Unpin>(
    state: &SharedState, user: &'a RpcHello<'a>, mut stream: S,
) -> Result<(), Error> {
    let db = &state.db;
    let server_name = state.server_name.as_str();

    trace!("waiting for client command");
    let req =
        match timeout(state.config.limits.command_timeout, rpc::read_packet(&mut stream)).await {
            Ok(res) => match res {
                Ok(v) => v,
                Err(e) => return Err(e),
            },
            Err(_) => {
                _ = RpcMessage::Fail(RpcFail {
                    code: 0,
                    message: &format!("{server_name} client idle for too long.\n"),
                })
                .async_write(&mut stream)
                .await;
                return Err(Error::Timeout);
            },
        };
    trace!("received client command");
    let req = match RpcMessage::deserialize(&req) {
        Ok(v) => v,
        Err(err) => {
            warn!(packet = %make_pretty_hex(&req), "received malformed RPC message");
            error!(error = %err, "failed to deserialize RPC message");
            let resp = rpc::RpcFail {
                code: 0,
                message: &format!("{server_name}: error: invalid data.\n"),
            };
            let resp = RpcMessage::Fail(resp);
            resp.async_write(&mut stream).await?;

            return Ok(());
        },
    };
    match req {
        RpcMessage::PullMetadata(md) => {
            let start = Instant::now();
            let funcs = match timeout(state.config.limits.pull_md_timeout, db.get_funcs(&md.funcs))
                .await
            {
                Ok(r) => match r {
                    Ok(v) => v,
                    Err(e) => {
                        error!(error = %e, requested_functions = md.funcs.len(), "failed to pull metadata from database");
                        rpc::RpcMessage::Fail(rpc::RpcFail {
                            code: 0,
                            message: &format!(
                                "{server_name}:  db error; please try again later..\n"
                            ),
                        })
                        .async_write(&mut stream)
                        .await?;
                        return Ok(());
                    },
                },
                Err(_) => {
                    RpcMessage::Fail(RpcFail {
                        code: 0,
                        message: &format!("{server_name}: query took too long to execute.\n"),
                    })
                    .async_write(&mut stream)
                    .await?;
                    debug!(timeout = ?state.config.limits.pull_md_timeout, "metadata pull timed out");
                    return Err(Error::Timeout);
                },
            };
            let pulled_funcs = funcs.iter().filter(|v| v.is_some()).count();
            state.metrics.pulls.inc_by(pulled_funcs as _);
            state.metrics.queried_funcs.inc_by(md.funcs.len() as _);
            debug!(
                pulled_functions = pulled_funcs,
                requested_functions = md.funcs.len(),
                elapsed = ?start.elapsed(),
                "metadata pull completed"
            );

            let statuses: Vec<u32> = funcs.iter().map(|v| u32::from(v.is_none())).collect();
            let found = funcs
                .into_iter()
                .flatten()
                .map(|v| rpc::PullMetadataResultFunc {
                    popularity: v.popularity,
                    len: v.len,
                    name: Cow::Owned(v.name),
                    mb_data: Cow::Owned(v.data),
                })
                .collect();

            RpcMessage::PullMetadataResult(rpc::PullMetadataResult {
                unk0: Cow::Owned(statuses),
                funcs: Cow::Owned(found),
            })
            .async_write(&mut stream)
            .await?;
        },
        RpcMessage::PushMetadata(mds) => {
            // parse the function's metadata
            let start = Instant::now();
            let scores: Vec<u32> = mds.funcs.iter().map(md::get_score).collect();

            let status = match db.push_funcs(user, &mds, &scores).await {
                Ok(v) => v.into_iter().map(u32::from).collect::<Vec<u32>>(),
                Err(err) => {
                    error!(error = %err, pushed_functions = mds.funcs.len(), "failed to push metadata to database");
                    rpc::RpcMessage::Fail(rpc::RpcFail {
                        code: 0,
                        message: &format!("{server_name}: db error; please try again later.\n"),
                    })
                    .async_write(&mut stream)
                    .await?;
                    return Ok(());
                },
            };
            state.metrics.pushes.inc_by(status.len() as _);
            let new_funcs =
                status.iter().fold(0u64, |counter, &v| if v > 0 { counter + 1 } else { counter });
            state.metrics.new_funcs.inc_by(new_funcs);
            debug!(
                pushed_functions = status.len(),
                new_functions = new_funcs,
                elapsed = ?start.elapsed(),
                "metadata push completed"
            );

            RpcMessage::PushMetadataResult(rpc::PushMetadataResult { status: Cow::Owned(status) })
                .async_write(&mut stream)
                .await?;
        },
        RpcMessage::DelHistory(req) => {
            let is_delete_allowed = state.config.lumina.allow_deletes.unwrap_or(false);
            if !is_delete_allowed {
                RpcMessage::Fail(rpc::RpcFail {
                    code: 2,
                    message: &format!("{server_name}: Delete command is disabled on this server."),
                })
                .async_write(&mut stream)
                .await?;
            } else {
                if let Err(err) = db.delete_metadata(&req).await {
                    error!(error = %err, requested_functions = req.funcs.len(), "failed to delete metadata");
                    RpcMessage::Fail(rpc::RpcFail {
                        code: 3,
                        message: &format!("{server_name}: db error, please try again later."),
                    })
                    .async_write(&mut stream)
                    .await?;
                    return Ok(());
                }
                RpcMessage::DelHistoryResult(rpc::DelHistoryResult {
                    deleted_mds: req.funcs.len() as u32,
                })
                .async_write(&mut stream)
                .await?;
            }
        },
        RpcMessage::GetFuncHistories(req) => {
            let limit = state.config.lumina.get_history_limit.unwrap_or(0);

            if limit == 0 {
                RpcMessage::Fail(rpc::RpcFail {
                    code: 4,
                    message: &format!(
                        "{server_name}: function histories are disabled on this server."
                    ),
                })
                .async_write(&mut stream)
                .await?;
                return Ok(());
            }

            let mut statuses = vec![];
            let mut res = vec![];
            for chksum in req.funcs.iter().map(|v| v.mb_hash) {
                let history = match db.get_func_histories(chksum, limit).await {
                    Ok(v) => v,
                    Err(err) => {
                        error!(error = ?err, requested_functions = req.funcs.len(), "failed to retrieve function histories");
                        RpcMessage::Fail(rpc::RpcFail {
                            code: 3,
                            message: &format!("{server_name}: db error, please try again later."),
                        })
                        .async_write(&mut stream)
                        .await?;
                        return Ok(());
                    },
                };
                let status = !history.is_empty() as u32;
                statuses.push(status);
                if history.is_empty() {
                    continue;
                }
                let log = history
                    .into_iter()
                    .map(|(updated, name, metadata)| rpc::FunctionHistory {
                        unk0: 0,
                        unk1: 0,
                        name: Cow::Owned(name),
                        metadata: Cow::Owned(metadata),
                        timestamp: updated.unix_timestamp() as u64,
                        author_idx: 0,
                        idb_path_idx: 0,
                    })
                    .collect::<Vec<_>>();
                res.push(rpc::FunctionHistories { log: Cow::Owned(log) });
            }

            trace!(
                returned_histories = res.len(),
                requested_functions = req.funcs.len(),
                "function history lookup completed"
            );

            RpcMessage::GetFuncHistoriesResult(rpc::GetFuncHistoriesResult {
                status: statuses.into(),
                funcs: Cow::Owned(res),
                users: vec![].into(),
                dbs: vec![].into(),
            })
            .async_write(&mut stream)
            .await?;
        },
        _ => {
            RpcMessage::Fail(rpc::RpcFail {
                code: 0,
                message: &format!("{server_name}: invalid data.\n"),
            })
            .async_write(&mut stream)
            .await?;
        },
    }
    Ok(())
}

async fn handle_client<S: AsyncRead + AsyncWrite + Unpin>(
    state: &SharedState, mut stream: S,
) -> Result<(), rpc::Error> {
    let server_name = &state.server_name;
    let hello = match timeout(state.config.limits.hello_timeout, rpc::read_packet(&mut stream))
        .await
    {
        Ok(v) => v?,
        Err(_) => {
            debug!(timeout = ?state.config.limits.hello_timeout, "client did not send hello before timeout");
            return Ok(());
        },
    };

    let (hello, creds) = match RpcMessage::deserialize(&hello) {
        Ok(RpcMessage::Hello(v, creds)) => {
            debug!(
                protocol_version = v.protocol_version,
                has_credentials = creds.is_some(),
                "received client hello"
            );
            (v, creds)
        },
        _ => {
            // send error
            error!("received invalid client hello");

            let resp = rpc::RpcFail { code: 0, message: &format!("{server_name}: bad sequence.") };
            let resp = rpc::RpcMessage::Fail(resp);
            resp.async_write(&mut stream).await?;

            return Ok(());
        },
    };
    state
        .metrics
        .lumina_version
        .get_or_create(&LuminaVersion { protocol_version: hello.protocol_version })
        .inc();

    if let Some(ref creds) = creds {
        if creds.username != "guest" {
            // Only allow "guest" to connect for now.
            rpc::RpcMessage::Fail(rpc::RpcFail {
                code: 1,
                message: &format!("{server_name}: invalid username or password. Try logging in with `guest` instead."),
            }).async_write(&mut stream).await?;
            return Ok(());
        }
    }

    let resp = match hello.protocol_version {
        0..=4 => rpc::RpcMessage::Ok(()),

        // starting IDA 8.3
        5.. => {
            let mut features = 0;

            if state.config.lumina.allow_deletes.unwrap_or(false) {
                features |= 0x02;
            }

            rpc::RpcMessage::HelloResult(HelloResult { features, ..Default::default() })
        },
    };
    resp.async_write(&mut stream).await?;

    loop {
        handle_transaction(state, &hello, &mut stream).await?;
    }
}

async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(state: &SharedState, mut s: S) {
    if let Err(ref err) = handle_client(state, &mut s).await {
        if discriminant(err) == discriminant(&Error::HttpReq) {
            warn!("received HTTP request on Lumina listener");
            const BAD_REQ_BODY: &str = include_str!("bad_req.html");

            if s.write_all(
                format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nServer: lumen\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
                    BAD_REQ_BODY.len()
                )
                .as_bytes(),
            )
            .await
            .is_ok()
            {
                let _ = s.write_all(BAD_REQ_BODY.as_bytes()).await;
            }
        } else if discriminant(err) != discriminant(&Error::Eof) {
            warn!(error = %err, "client connection failed");
        }
    }
}

async fn serve(
    listener: TcpListener, accpt: Option<tokio_native_tls::TlsAcceptor>, state: SharedState,
    mut shutdown_signal: tokio::sync::oneshot::Receiver<()>,
) {
    let accpt = accpt.map(Arc::new);

    let (async_drop, worker) = AsyncDropper::new();
    tokio::task::spawn(worker);

    let connections = Arc::new(tokio::sync::Mutex::new(HashMap::<
        std::net::SocketAddr,
        tokio::task::JoinHandle<()>,
    >::new()));

    loop {
        let (client, addr) = tokio::select! {
            _ = &mut shutdown_signal => {
                drop(state);
                info!("shutting down listener");
                let m = connections.lock().await;
                m.iter().for_each(|(k, v)| {
                    debug!(client_addr = %k, "aborting active client connection");
                    v.abort();
                });
                return;
             },
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(err) => {
                    warn!(error = %err, "failed to accept client connection");
                    continue;
                }
            },
        };

        let start = Instant::now();

        let state = state.clone();
        let accpt = accpt.clone();

        let tls = accpt.is_some();
        let connection_span = info_span!("connection", client_addr = %addr, tls);

        let conns2 = connections.clone();
        let counter = state.metrics.active_connections.clone();
        let close_span = connection_span.clone();
        let guard = async_drop.defer(async move {
            let count = counter.dec() - 1;
            debug!(
                parent: &close_span,
                elapsed = ?start.elapsed(),
                active_connections = count,
                "client connection closed"
            );

            let mut guard = conns2.lock().await;
            if guard.remove(&addr).is_none() {
                error!(parent: &close_span, "connection was not registered during cleanup");
            }
        });

        let counter = state.metrics.active_connections.clone();
        let handle = tokio::spawn(
            async move {
                let _guard = guard;
                let count = { counter.inc() + 1 };
                debug!(active_connections = count, "accepted client connection");
                match accpt {
                Some(accpt) => {
                    match timeout(state.config.limits.tls_handshake_timeout, accpt.accept(client))
                        .await
                    {
                        Ok(r) => match r {
                            Ok(s) => {
                                handle_connection(&state, s).await;
                            },
                            Err(err) => {
                                debug!(client_addr = %addr, error = %err, "TLS handshake failed")
                            },
                        },
                        Err(_) => {
                            debug!(
                                client_addr = %addr,
                                timeout = ?state.config.limits.tls_handshake_timeout,
                                "TLS handshake timed out"
                            );
                        },
                    };
                },
                    None => handle_connection(&state, client).await,
                }
            }
            .instrument(connection_span),
        );

        let mut guard = connections.lock().await;
        guard.insert(addr, handle);
    }
}

pub(crate) async fn do_lumen(config: Arc<Config>) {
    info!("starting private Lumina server");

    let db = match Database::open(&config.database).await {
        Ok(v) => v,
        Err(err) => {
            error!(error = %err, "failed to open database");
            exit(1);
        },
    };

    let server_name = config.lumina.server_name.clone().unwrap_or_else(|| String::from("lumen"));

    let state = Arc::new(SharedState_ {
        db,
        config,
        server_name,
        metrics: common::metrics::Metrics::default(),
    });

    let web_handle = if let Some(ref webcfg) = state.config.api_server {
        let bind_addr = webcfg.bind_addr;
        let state = state.clone();
        info!(bind_addr = %bind_addr, "starting HTTP API server");
        Some(tokio::spawn(async move {
            web::start_webserver(bind_addr, state).await;
        }))
    } else {
        None
    };

    if state.config.lumina.listeners.is_empty() {
        error!("no Lumina listeners are configured");
        exit(1);
    }

    let mut shutdown_senders = vec![];
    let mut server_handles = vec![];
    for listener in &state.config.lumina.listeners {
        let tls_acceptor = if let Some(tls) = &listener.tls {
            let mut cert = match std::fs::read(&tls.server_cert) {
                Ok(v) => v,
                Err(err) => {
                    error!(cert_path = %tls.server_cert.display(), error = %err, "failed to read TLS certificate");
                    exit(1);
                },
            };
            let password = std::env::var("PKCSPASSWD").unwrap_or_default();
            let identity = match Identity::from_pkcs12(&cert, &password) {
                Ok(v) => v,
                Err(err) => {
                    error!(cert_path = %tls.server_cert.display(), error = %err, "failed to parse TLS certificate");
                    exit(1);
                },
            };
            cert.fill(0);
            let mut acceptor = native_tls::TlsAcceptor::builder(identity);
            acceptor.min_protocol_version(Some(native_tls::Protocol::Sslv3));
            match acceptor.build() {
                Ok(v) => Some(tokio_native_tls::TlsAcceptor::from(v)),
                Err(err) => {
                    error!(cert_path = %tls.server_cert.display(), error = %err, "failed to build TLS acceptor");
                    exit(1);
                },
            }
        } else {
            None
        };

        let server = match TcpListener::bind(listener.bind_addr).await {
            Ok(v) => v,
            Err(err) => {
                error!(bind_addr = %listener.bind_addr, error = %err, "failed to bind Lumina listener");
                exit(1);
            },
        };
        info!(bind_addr = %server.local_addr().unwrap(), tls = tls_acceptor.is_some(), "Lumina listener ready");

        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();
        shutdown_senders.push(shutdown_sender);
        let state = state.clone();
        server_handles.push(tokio::spawn(async move {
            serve(server, tls_acceptor, state, shutdown_receiver).await;
        }));
    }

    tokio::signal::ctrl_c().await.unwrap();
    debug!("received shutdown signal");
    if let Some(handle) = web_handle {
        handle.abort();
    }
    for sender in shutdown_senders {
        let _ = sender.send(());
    }
    for handle in server_handles {
        handle.await.unwrap();
    }

    info!("Lumina server stopped");
}
