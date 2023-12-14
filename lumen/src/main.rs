// Copyright (C) 2022 Naim A. <naim@abda.nl>

#![forbid(unsafe_code)]
#![warn(unused_crate_dependencies)]
#![deny(clippy::all)]

use common::async_drop::AsyncDropper;
use common::metrics::LuminaVersion;
use common::rpc::{RpcHello, RpcFail, HelloResult};
use native_tls::Identity;
use clap::Arg;
use log::*;
use tokio::time::timeout;
use std::collections::HashMap;
use std::mem::discriminant;
use std::time::{Duration, Instant};
use std::{borrow::Cow, sync::Arc};
use tokio::{net::TcpListener, io::AsyncWrite, io::AsyncRead};
use std::process::exit;
use common::{SharedState, SharedState_};

mod web;

use common::{config, make_pretty_hex, md, rpc::{self, Error}};
use common::db::Database;
use rpc::RpcMessage;

fn setup_logger() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", concat!(env!("CARGO_PKG_NAME"), "=info"));
    }
    pretty_env_logger::init_timed();
}

async fn handle_transaction<'a, S: AsyncRead + AsyncWrite + Unpin>(state: &SharedState, user: &'a RpcHello<'a>, mut stream: S) -> Result<(), Error> {
    let db = &state.db;
    let server_name = state.server_name.as_str();

    trace!("waiting for command..");
    let req = match timeout(Duration::from_secs(3600), rpc::read_packet(&mut stream)).await {
        Ok(res) => match res {
            Ok(v) => v,
            Err(e) => return Err(e),
        },
        Err(_) => {
            _ = RpcMessage::Fail(RpcFail {
                code: 0,
                message: &format!("{server_name} client idle for too long.\n"),
            }).async_write(&mut stream).await;
            return Err(Error::Timeout);
        },
    };
    trace!("got command!");
    let req = match RpcMessage::deserialize(&req) {
        Ok(v) => v,
        Err(err) => {
            warn!("bad message: \n{}\n", make_pretty_hex(&req));
            error!("failed to process rpc message: {}", err);
            let resp = rpc::RpcFail{ code: 0, message: &format!("{server_name}: error: invalid data.\n")};
            let resp = RpcMessage::Fail(resp);
            resp.async_write(&mut stream).await?;

            return Ok(());
        },
    };
    match req {
        RpcMessage::PullMetadata(md) => {
            let start = Instant::now();
            let funcs = match timeout(Duration::from_secs(4 * 60),  db.get_funcs(&md.funcs)).await {
                Ok(r) => match r {
                    Ok(v) => v,
                    Err(e) => {
                        error!("pull failed, db: {}", e);
                        rpc::RpcMessage::Fail(rpc::RpcFail {
                            code: 0,
                            message: &format!("{server_name}:  db error; please try again later..\n")
                        }).async_write(&mut stream).await?;
                        return Ok(());
                    },
                },
                Err(_) => {
                    RpcMessage::Fail(RpcFail {
                        code: 0,
                        message: &format!("{server_name}: query took too long to execute.\n"),
                    }).async_write(&mut stream).await?;
                    debug!("pull query timeout");
                    return Err(Error::Timeout);
                }
            };
            let pulled_funcs = funcs.iter().filter(|v| v.is_some()).count();
            state.metrics.pulls.inc_by(pulled_funcs as _);
            state.metrics.queried_funcs.inc_by(md.funcs.len() as _);
            debug!("pull {pulled_funcs}/{} funcs ended after {:?}", md.funcs.len(), start.elapsed());

            let statuses: Vec<u32> = funcs.iter().map(|v| u32::from(v.is_none())).collect();
            let found = funcs
                .into_iter()
                .flatten()
                .map(|v| {
                    rpc::PullMetadataResultFunc {
                        popularity: v.popularity,
                        len: v.len,
                        name: Cow::Owned(v.name),
                        mb_data: Cow::Owned(v.data),
                    }
                }).collect();

            RpcMessage::PullMetadataResult(rpc::PullMetadataResult{
                unk0: Cow::Owned(statuses),
                funcs: Cow::Owned(found),
            }).async_write(&mut stream).await?;
        },
        RpcMessage::PushMetadata(mds) => {
            // parse the function's metadata
            let start = Instant::now();
            let scores: Vec<u32> = mds.funcs.iter()
                .map(md::get_score)
                .collect();

            let status = match db.push_funcs(user, &mds, &scores).await {
                Ok(v) => {
                    v.into_iter().map(u32::from).collect::<Vec<u32>>()
                },
                Err(err) => {
                    log::error!("push failed, db: {}", err);
                    rpc::RpcMessage::Fail(rpc::RpcFail {
                        code: 0,
                        message: &format!("{server_name}: db error; please try again later.\n")
                    }).async_write(&mut stream).await?;
                    return Ok(());
                }
            };
            state.metrics.pushes.inc_by(status.len() as _);
            let new_funcs = status
                .iter()
                .fold(0u64, |counter, &v| if v > 0 { counter + 1 } else {counter});
            state.metrics.new_funcs.inc_by(new_funcs);
            debug!("push {} funcs ended after {:?} ({new_funcs} new)", status.len(), start.elapsed());

            RpcMessage::PushMetadataResult(rpc::PushMetadataResult {
                status: Cow::Owned(status),
            }).async_write(&mut stream).await?;
        },
        RpcMessage::DelHistory(req) => {
            let is_delete_allowed = state.config.lumina.allow_deletes.unwrap_or(false);
            if !is_delete_allowed {
                RpcMessage::Fail(rpc::RpcFail {
                    code: 2,
                    message: &format!("{server_name}: Delete command is disabled on this server.")
                }).async_write(&mut stream).await?;
            } else {
                if let Err(err) = db.delete_metadata(&req).await {
                    error!("delete failed. db: {err}");
                    RpcMessage::Fail(rpc::RpcFail {
                        code: 3,
                        message: &format!("{server_name}: db error, please try again later.")
                    }).async_write(&mut stream).await?;
                    return Ok(());
                }
                RpcMessage::DelHistoryResult(rpc::DelHistoryResult {
                    deleted_mds: req.funcs.len() as u32,
                }).async_write(&mut stream).await?;
            }
        },
        _ => {
            RpcMessage::Fail(rpc::RpcFail{code: 0, message: &format!("{server_name}: invalid data.\n")}).async_write(&mut stream).await?;
        }
    }
    Ok(())
}

async fn handle_client<S: AsyncRead + AsyncWrite + Unpin>(state: &SharedState, mut stream: S) -> Result<(), rpc::Error> {
    let server_name = &state.server_name;
    let hello = match timeout(Duration::from_secs(15), rpc::read_packet(&mut stream)).await {
        Ok(v) => v?,
        Err(_) => {
            debug!("didn't get hello in time.");
            return Ok(());
        },
    };

    let (hello, creds) = match RpcMessage::deserialize(&hello) {
        Ok(RpcMessage::Hello(v, creds)) => {
            debug!("hello protocol={}, login creds: {creds:?}", v.protocol_version);
            (v, creds)
        },
        _ => {
            // send error
            error!("got bad hello message");

            let resp = rpc::RpcFail{ code: 0, message: &format!("{server_name}: bad sequence.") };
            let resp = rpc::RpcMessage::Fail(resp);
            resp.async_write(&mut stream).await?;

            return Ok(());
        }
    };
    state.metrics.lumina_version.get_or_create(&LuminaVersion {
        protocol_version: hello.protocol_version,
    }).inc();

    if let Some(ref creds) = creds {

        let auth_state = state.db.auth_user(creds.username, creds.password).await;

        if !auth_state.is_ok() || !auth_state.unwrap() {
            // Only allow "guest" to connect for now.
            rpc::RpcMessage::Fail(rpc::RpcFail {
                code: 1,
                message: &format!("{server_name}: invalid username or password."),
            }).async_write(&mut stream).await?;
            return Ok(());
        }
    }
    else {
        rpc::RpcMessage::Fail(rpc::RpcFail {
            code: 1,
            message: &format!("{server_name}: username and password should be specified."),
        }).async_write(&mut stream).await?;
        return Ok(());
    }

    let resp = match hello.protocol_version {
        0..=4 => rpc::RpcMessage::Ok(()),

        // starting IDA 8.3
        5.. => rpc::RpcMessage::HelloResult(HelloResult {
            unk0: "".into(),
            unk1: "".into(),
            unk2: "".into(),
            unk3: "".into(),
            unk4: 0,
            unk5: 0,
            unk6: 0,
        })
    };
    resp.async_write(&mut stream).await?;

    loop {
        handle_transaction(state, &hello, &mut stream).await?;
    }
}

async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(state: &SharedState, s: S) {
    if let Err(err) = handle_client(state, s).await {
        if discriminant(&err) != discriminant(&Error::Eof) {
            warn!("err: {}", err);
        }
    }
}

async fn serve(listener: TcpListener, accpt: Option<tokio_native_tls::TlsAcceptor>, state: SharedState, mut shutdown_signal: tokio::sync::oneshot::Receiver<()>) {
    let accpt = accpt.map(Arc::new);

    let (async_drop, worker) = AsyncDropper::new();
    tokio::task::spawn(worker);

    let connections = Arc::new(tokio::sync::Mutex::new(HashMap::<std::net::SocketAddr, tokio::task::JoinHandle<()>>::new()));

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
            debug!("connection with {:?} ended after {:?}; {} active connections", addr, start.elapsed(), count);

            let mut guard = conns2.lock().await;
            if guard.remove(&addr).is_none() {
                error!("Couldn't remove connection from set {addr}");
            }
        });

        let counter = state.metrics.active_connections.clone();
        let handle = tokio::spawn(async move {
            let _guard = guard;
            let count = {
                counter.inc() + 1
            };
            let protocol = if accpt.is_some() {" [TLS]"} else {""};
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

fn main() {
    setup_logger();
    let matches = clap::Command::new("lumen")
        .version(env!("CARGO_PKG_VERSION"))
        .about("lumen is a private Lumina server for IDA.\nVisit https://github.com/naim94a/lumen/ for updates.")
        .author("Naim A. <naim@abda.nl>")
        .arg(
            Arg::new("config")
                .short('c')
                .required(true)
                .default_value("config.toml")
                .help("Configuration file path")
        )
        .subcommand(
            clap::Command::new("add_user")
            .about("Adds a new user")
            .arg(Arg::new("username")
                .help("The username for the new user")
                .required(true))
            .arg(Arg::new("password")
                .help("The password for the new user")
                .required(true))
        )
        .subcommand(
            clap::Command::new("change_user_pass")
            .about("Changes a user's password")
            .arg(Arg::new("username")
                .help("The username of the user")
                .required(true))
            .arg(Arg::new("new_password")
                .help("The new password for the user")
                .required(true))
        )
        .subcommand(
            clap::Command::new("remove_user")
            .about("Removes user")
            .arg(Arg::new("username")
                .help("The username of the user")
                .required(true))
        )
        .get_matches();

    let config = {
        config::load_config(std::fs::File::open(matches.get_one::<String>("config").unwrap()).expect("failed to read config"))
    };
    let config = Arc::new(config);

    info!("starting private lumen server...");

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build() {
        Ok(v) => v,
        Err(err) => {
            error!("failed to create tokio runtime: {}", err);
            exit(1);
        },
    };

    let db = rt.block_on(async {
        match Database::open(&config.database).await {
            Ok(v) => v,
            Err(err) => {
                error!("failed to open database: {}", err);
                exit(1);
            }
        }
    });

    let server_name = config.lumina.server_name.clone().unwrap_or_else(|| String::from("lumen"));

    let state = Arc::new(SharedState_{
        db,
        config,
        server_name,
        metrics: common::metrics::Metrics::default(),
    });

    let subcommand_future = async {
        match matches.subcommand() {
            Some(("add_user", sub_m)) => {
                let username = sub_m.get_one::<String>("username").unwrap();
                let password = sub_m.get_one::<String>("password").unwrap();

                match state.db.register_user(username, password).await {
                    Ok(_) => println!("User added successfully"),
                    Err(e) => eprintln!("Error adding user: {}", e),
                }
                exit(0);
            },
            Some(("change_user_pass", sub_m)) => {
                let username = sub_m.get_one::<String>("username").unwrap();
                let new_password = sub_m.get_one::<String>("new_password").unwrap();

                match state.db.change_user_password(username, new_password).await {
                    Ok(_) => println!("User password changed successfully"),
                    Err(e) => eprintln!("Error changing user password: {}", e),
                }
                exit(0);
            },
            Some(("remove_user", sub_m)) => {
                let username = sub_m.get_one::<String>("username").unwrap();

                match state.db.remove_user(username).await {
                    Ok(_) => println!("User removed successfully"),
                    Err(e) => eprintln!("Error removing user: {}", e),
                }
                exit(0);
            },
            _ => {
                
            }
        }
    };

    rt.block_on(subcommand_future);

    let tls_acceptor;
    if state.config.lumina.use_tls.unwrap_or_default() {
        let cert_path = &state.config.lumina.tls.as_ref().expect("tls section is missing").server_cert;
        let mut crt = match std::fs::read(cert_path) {
            Ok(v) => v,
            Err(err) => {
                error!("failed to read certificate file: {}", err);
                exit(1);
            }
        };
        let pkcs_passwd = std::env::var("PKCSPASSWD").unwrap_or_default();
        let id = match Identity::from_pkcs12(&crt, &pkcs_passwd) {
            Ok(v) => v,
            Err(err) => {
                error!("failed to parse tls certificate: {}", err);
                exit(1);
            }
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
        Some(rt.spawn(async move {
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

    rt.block_on(async {
        let server_handle = tokio::task::spawn(async_server);
        tokio::signal::ctrl_c().await.unwrap();
        debug!("CTRL-C; exiting...");
        if let Some(handle) = web_handle {
            handle.abort();
        }
        exit_signal_tx.send(()).unwrap();
        server_handle.await.unwrap();
    });
    drop(rt);
    info!("Goodbye.");
}
