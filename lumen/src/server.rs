use std::{
    borrow::Cow,
    collections::HashMap,
    mem::discriminant,
    process::exit,
    sync::Arc,
    time::{Duration, Instant},
};

use common::{
    async_drop::AsyncDropper,
    config::Config,
    db::{self, Database},
    make_pretty_hex, md,
    metrics::LuminaVersion,
    rpc::{self, Creds, Error, HelloResult, RpcFail, RpcHello, RpcMessage},
    SharedState, SharedState_,
};
use log::{debug, error, info, trace, warn};
use native_tls::Identity;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    time::timeout,
};

use crate::web;

struct Session<'a> {
    state: &'a SharedState_,
    hello_msg: RpcHello<'a>,
    _creds: db::schema::Creds<'a>,
    creds_id: Option<i32>,
    last_cred_check: Instant,
}
impl<'a> Session<'a> {
    /// Check if the user changed in the database.
    pub async fn is_valid(&mut self) -> bool {
        let db = &self.state.db;
        if let Some(cred_id) = self.creds_id {
            if self.last_cred_check.elapsed() > Duration::from_secs(60 * 5) {
                match db.get_user_by_id(cred_id).await {
                    Ok(v) => {
                        if !v.is_enabled
                            || v.is_admin != self._creds.is_admin
                            || v.passwd_salt != self._creds.passwd_salt
                        {
                            // user changed, force them to login again.
                            return false;
                        }
                        self.last_cred_check = Instant::now();
                        return true;
                    },
                    Err(err) => {
                        error!("db error: {err}");
                        return false;
                    },
                }
            }
        }
        true
    }
}

async fn handle_transaction<'a, S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut Session<'a>, mut stream: S,
) -> Result<(), Error> {
    let state = session.state;
    let db = &state.db;
    let server_name = state.server_name.as_str();

    trace!("waiting for command..");
    let rpkt = async {
        let hdr = rpc::read_packet_header(&mut stream).await?;
        // we don't want to read a whole request just to find out the user was revoked...
        if !session.is_valid().await {
            return Err(Error::Timeout);
        }
        hdr.read(&mut stream).await
    };
    let req = match timeout(Duration::from_secs(3600), rpkt).await {
        Ok(res) => match res {
            Ok(v) => v,
            Err(e) => return Err(e),
        },
        Err(_) => {
            _ = RpcMessage::Fail(RpcFail {
                result: 0,
                error: &format!("{server_name} client idle for too long.\n"),
            })
            .async_write(&mut stream)
            .await;
            return Err(Error::Timeout);
        },
    };
    trace!("got command!");

    if !session.is_valid().await {
        return Err(Error::Timeout);
    }

    let req = match RpcMessage::deserialize(&req) {
        Ok(v) => v,
        Err(err) => {
            warn!("bad message: \n{}\n", make_pretty_hex(&req));
            error!("failed to process rpc message: {}", err);
            let resp = rpc::RpcFail {
                result: 0,
                error: &format!("{server_name}: error: invalid data.\n"),
            };
            let resp = RpcMessage::Fail(resp);
            resp.async_write(&mut stream).await?;

            return Ok(());
        },
    };
    match req {
        RpcMessage::PullMetadata(md) => {
            let start = Instant::now();
            let funcs = match timeout(Duration::from_secs(4 * 60), db.get_funcs(&md.pattern_ids))
                .await
            {
                Ok(r) => match r {
                    Ok(v) => v,
                    Err(e) => {
                        error!("pull failed, db: {}", e);
                        rpc::RpcMessage::Fail(rpc::RpcFail {
                            result: 0,
                            error: &format!("{server_name}:  db error; please try again later..\n"),
                        })
                        .async_write(&mut stream)
                        .await?;
                        return Ok(());
                    },
                },
                Err(_) => {
                    RpcMessage::Fail(RpcFail {
                        result: 0,
                        error: &format!("{server_name}: query took too long to execute.\n"),
                    })
                    .async_write(&mut stream)
                    .await?;
                    debug!("pull query timeout");
                    return Err(Error::Timeout);
                },
            };
            let pulled_funcs = funcs.iter().filter(|v| v.is_some()).count();
            state.metrics.pulls.inc_by(pulled_funcs as _);
            state.metrics.queried_funcs.inc_by(md.pattern_ids.len() as _);
            debug!(
                "pull {pulled_funcs}/{} funcs ended after {:?}",
                md.pattern_ids.len(),
                start.elapsed()
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
                codes: Cow::Owned(statuses),
                funcs: Cow::Owned(found),
            })
            .async_write(&mut stream)
            .await?;
        },
        RpcMessage::PushMetadata(mds) => {
            // parse the function's metadata
            let start = Instant::now();
            let scores: Vec<u32> = mds.funcs.iter().map(md::get_score).collect();

            let status =
                match db.push_funcs(&session.hello_msg, session.creds_id, &mds, &scores).await {
                    Ok(v) => v.into_iter().map(u32::from).collect::<Vec<u32>>(),
                    Err(err) => {
                        log::error!("push failed, db: {}", err);
                        rpc::RpcMessage::Fail(rpc::RpcFail {
                            result: 0,
                            error: &format!("{server_name}: db error; please try again later.\n"),
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
                "push {} funcs ended after {:?} ({new_funcs} new)",
                status.len(),
                start.elapsed()
            );

            RpcMessage::PushMetadataResult(rpc::PushMetadataResult { status: Cow::Owned(status) })
                .async_write(&mut stream)
                .await?;
        },
        RpcMessage::DelHistory(req) => {
            let is_delete_allowed = state.config.lumina.allow_deletes.unwrap_or(false);
            if !is_delete_allowed {
                RpcMessage::Fail(rpc::RpcFail {
                    result: 2,
                    error: &format!("{server_name}: Delete command is disabled on this server."),
                })
                .async_write(&mut stream)
                .await?;
            } else {
                if let Err(err) = db.delete_metadata(&req).await {
                    error!("delete failed. db: {err}");
                    RpcMessage::Fail(rpc::RpcFail {
                        result: 3,
                        error: &format!("{server_name}: db error, please try again later."),
                    })
                    .async_write(&mut stream)
                    .await?;
                    return Ok(());
                }
                RpcMessage::DelHistoryResult(rpc::DelHistoryResult {
                    ndeleted: req.calcrel_hashes.len() as u32,
                })
                .async_write(&mut stream)
                .await?;
            }
        },
        RpcMessage::GetFuncHistories(req) => {
            let limit = state.config.lumina.get_history_limit.unwrap_or(0);

            if limit == 0 {
                RpcMessage::Fail(rpc::RpcFail {
                    result: 4,
                    error: &format!(
                        "{server_name}: function histories are disabled on this server."
                    ),
                })
                .async_write(&mut stream)
                .await?;
                return Ok(());
            }

            let mut statuses = vec![];
            let mut res = vec![];
            for chksum in req.funcs.iter().map(|v| v.data) {
                let history = match db.get_func_histories(chksum, limit).await {
                    Ok(v) => v,
                    Err(err) => {
                        error!("failed to get function histories: {err:?}");
                        RpcMessage::Fail(rpc::RpcFail {
                            result: 3,
                            error: &format!("{server_name}: db error, please try again later."),
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

            trace!("returning {} histories", res.len());

            RpcMessage::GetFuncHistoriesResult(rpc::GetFuncHistoriesResult {
                status: statuses.into(),
                funcs: Cow::Owned(res),
                authors: vec![].into(),
                idb_paths: vec![].into(),
            })
            .async_write(&mut stream)
            .await?;
        },
        _ => {
            RpcMessage::Fail(rpc::RpcFail {
                result: 0,
                error: &format!("{server_name}: invalid data.\n"),
            })
            .async_write(&mut stream)
            .await?;
        },
    }
    Ok(())
}

async fn http_reply<W: AsyncRead + AsyncWrite + Unpin>(mut stream: W) {
    use tokio::io::AsyncWriteExt;

    const HTTP_REPLY: &str = concat!(
        "HTTP/1.1 400 bad request\r\n",
        "Refresh: 2; URL=https://github.com/naim94a/lumen\r\n",
        "Server: lumen\r\n",
        "Connection: close\r\n",
        "Content-Type: text/html\r\n",
        "",
        "\r\n",
        "<pre>This is not an HTTP server. <br />Redirecting to <a href=\"https://github.com/naim94a/lumen\">lumen</a> ...</pre>\n",
    );

    let _ = stream.write_all(HTTP_REPLY.as_bytes()).await;
}

async fn handle_client<S: AsyncRead + AsyncWrite + Unpin>(
    state: &SharedState, mut stream: S,
) -> Result<(), rpc::Error> {
    let server_name = &state.server_name;
    let rpkt = async {
        let hdr = rpc::read_packet_header(&mut stream).await?;
        if hdr.is_http() {
            // looks like someone is using a browser instead of IDA, what a fool.
            debug!("ignoring http request...");
            http_reply(&mut stream).await;
            return Err(Error::Eof);
        }
        hdr.read(&mut stream).await
    };
    let hello = match timeout(Duration::from_secs(15), rpkt).await {
        Ok(v) => v?,
        Err(_) => {
            debug!("didn't get hello in time.");
            return Ok(());
        },
    };

    let (hello, creds) = match RpcMessage::deserialize(&hello) {
        Ok(RpcMessage::Hello(v, creds)) => {
            debug!("hello protocol={}, login creds: {creds:?}", v.client_version);
            (v, creds)
        },
        _ => {
            // send error
            error!("got bad hello message");

            let resp = rpc::RpcFail { result: 0, error: &format!("{server_name}: bad sequence.") };
            let resp = rpc::RpcMessage::Fail(resp);
            resp.async_write(&mut stream).await?;

            return Ok(());
        },
    };
    state
        .metrics
        .lumina_version
        .get_or_create(&LuminaVersion { protocol_version: hello.client_version })
        .inc();

    let creds = creds.unwrap_or(Creds { username: "guest", password: "guest" });

    let user = if creds.username != "guest" {
        match state.db.get_user_by_username(creds.username).await {
            Ok((user_id, db_creds)) if db_creds.verify_password(creds.password) => {
                let _ = state.db.update_last_active(user_id).await;
                info!("{} logged in successfully.", db_creds.username);
                (user_id, db_creds)
            },
            Ok(_) => {
                rpc::RpcMessage::Fail(rpc::RpcFail {
                    result: 1,
                    error: &format!("{server_name}: invalid username or password."),
                })
                .async_write(&mut stream)
                .await?;
                return Ok(());
            },
            Err(err) => {
                error!("error while fetching user information: {err}");
                rpc::RpcMessage::Fail(rpc::RpcFail {
                    result: 1,
                    error: &format!("{server_name}: internal error, please try again later."),
                })
                .async_write(&mut stream)
                .await?;
                return Ok(());
            },
        }
    } else {
        (
            -1,
            db::schema::Creds {
                username: creds.username.into(),
                is_enabled: state.config.users.allow_guests,
                ..Default::default()
            },
        )
    };

    if !user.1.is_enabled {
        info!("attempt to login to disabled account [{}].", user.1.username);
        rpc::RpcMessage::Fail(rpc::RpcFail {
            result: 1,
            error: &format!("{server_name}: account disabled."),
        })
        .async_write(&mut stream)
        .await?;
        return Ok(());
    }

    let resp = match hello.client_version {
        0..=4 => rpc::RpcMessage::Ok(()),

        // starting IDA 8.3
        5.. => {
            let mut features = 0;

            if user.1.is_admin {
                features |= 0x01;
            }

            if user.0 != -1 && state.config.lumina.allow_deletes.unwrap_or(false) {
                features |= 0x02;
            }

            let last_active = user.1.last_active.map_or(0, |v| v.unix_timestamp() as u64);

            rpc::RpcMessage::HelloResult(HelloResult {
                username: Cow::Borrowed(&user.1.username),
                last_active,
                features,
                ..Default::default()
            })
        },
    };
    resp.async_write(&mut stream).await?;

    let creds_id = if user.0 == -1 { None } else { Some(user.0) };
    let mut session = Session {
        state,
        hello_msg: hello,
        _creds: user.1,
        creds_id,
        last_cred_check: Instant::now(),
    };

    loop {
        handle_transaction(&mut session, &mut stream).await?;
    }
}

async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(state: &SharedState, s: S) {
    if let Err(err) = handle_client(state, s).await {
        if discriminant(&err) != discriminant(&Error::Eof) {
            warn!("err: {}", err);
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
                info!("shutting down...");
                let m = connections.lock().await;
                m.iter().for_each(|(k, v)| {
                    debug!("aborting task for {k}...");
                    v.abort();
                });
                return;
             },
            res = listener.accept() => match res {
                Ok(v) => v,
                Err(err) => {
                    warn!("failed to accept(): {}", err);
                    continue;
                }
            },
        };

        let start = Instant::now();

        let state = state.clone();
        let accpt = accpt.clone();

        let conns2 = connections.clone();
        let counter = state.metrics.active_connections.clone();
        let guard = async_drop.defer(async move {
            let count = counter.dec() - 1;
            debug!(
                "connection with {:?} ended after {:?}; {} active connections",
                addr,
                start.elapsed(),
                count
            );

            let mut guard = conns2.lock().await;
            if guard.remove(&addr).is_none() {
                error!("Couldn't remove connection from set {addr}");
            }
        });

        let counter = state.metrics.active_connections.clone();
        let handle = tokio::spawn(async move {
            let _guard = guard;
            let count = { counter.inc() + 1 };
            let protocol = if accpt.is_some() { " [TLS]" } else { "" };
            debug!("Connection from {:?}{}: {} active connections", &addr, protocol, count);
            match accpt {
                Some(accpt) => {
                    match timeout(Duration::from_secs(10), accpt.accept(client)).await {
                        Ok(r) => match r {
                            Ok(s) => {
                                handle_connection(&state, s).await;
                            },
                            Err(err) => debug!("tls accept ({}): {}", &addr, err),
                        },
                        Err(_) => {
                            debug!("client {} didn't complete ssl handshake in time.", &addr);
                        },
                    };
                },
                None => handle_connection(&state, client).await,
            }
        });

        let mut guard = connections.lock().await;
        guard.insert(addr, handle);
    }
}

pub(crate) async fn do_lumen(config: Arc<Config>) {
    info!("starting private lumen server...");

    let db = match Database::open(&config.database).await {
        Ok(v) => v,
        Err(err) => {
            error!("failed to open database: {}", err);
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

    let tls_acceptor;

    if state.config.lumina.use_tls.unwrap_or_default() {
        let cert_path =
            &state.config.lumina.tls.as_ref().expect("tls section is missing").server_cert;
        let mut crt = match std::fs::read(cert_path) {
            Ok(v) => v,
            Err(err) => {
                error!("failed to read certificate file: {}", err);
                exit(1);
            },
        };
        let pkcs_passwd = std::env::var("PKCSPASSWD").unwrap_or_default();
        let id = match Identity::from_pkcs12(&crt, &pkcs_passwd) {
            Ok(v) => v,
            Err(err) => {
                error!("failed to parse tls certificate: {}", err);
                exit(1);
            },
        };
        let _ = pkcs_passwd;
        crt.iter_mut().for_each(|v| *v = 0);
        let _ = crt;
        let mut accpt = native_tls::TlsAcceptor::builder(id);
        accpt.min_protocol_version(Some(native_tls::Protocol::Sslv3));
        let accpt = match accpt.build() {
            Ok(v) => v,
            Err(err) => {
                error!("failed to build tls acceptor: {}", err);
                exit(1);
            },
        };
        let accpt = tokio_native_tls::TlsAcceptor::from(accpt);
        tls_acceptor = Some(accpt);
    } else {
        tls_acceptor = None;
    }

    let web_handle = if let Some(ref webcfg) = state.config.api_server {
        let bind_addr = webcfg.bind_addr;
        let state = state.clone();
        info!("starting http api server on {:?}", &bind_addr);
        Some(tokio::spawn(async move {
            web::start_webserver(bind_addr, state).await;
        }))
    } else {
        None
    };

    let (exit_signal_tx, exit_signal_rx) = tokio::sync::oneshot::channel::<()>();

    let async_server = async move {
        let server = match TcpListener::bind(state.config.lumina.bind_addr).await {
            Ok(v) => v,
            Err(err) => {
                error!("failed to bind server port: {}", err);
                exit(1);
            },
        };

        info!("listening on {:?} secure={}", server.local_addr().unwrap(), tls_acceptor.is_some());

        serve(server, tls_acceptor, state, exit_signal_rx).await;
    };

    let server_handle = tokio::task::spawn(async_server);
    tokio::signal::ctrl_c().await.unwrap();
    debug!("CTRL-C; exiting...");
    if let Some(handle) = web_handle {
        handle.abort();
    }
    exit_signal_tx.send(()).unwrap();
    server_handle.await.unwrap();

    info!("Goodbye.");
}
