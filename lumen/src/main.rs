// Copyright (C) 2022 Naim A. <naim@abda.nl>

#![forbid(unsafe_code)]
#![warn(unused_crate_dependencies)]
#![deny(clippy::all)]

use common::rpc::{RpcHello, RpcFail};
use native_tls::Identity;
use clap::Arg;
use log::*;
use tokio::time::timeout;
use std::mem::discriminant;
use std::sync::atomic::{AtomicU32, Ordering};
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
            let funcs = match timeout(Duration::from_secs(60 * 60),  db.get_funcs(&md.funcs)).await {
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
            debug!("pull {} funcs ended after {:?}", funcs.len(), start.elapsed());

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
            debug!("push {} funcs ended after {:?}", status.len(), start.elapsed());

            RpcMessage::PushMetadataResult(rpc::PushMetadataResult {
                status: Cow::Owned(status),
            }).async_write(&mut stream).await?;
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

            let resp = rpc::RpcFail{ code: 0, message: &format!("{}: bad sequence.\n", server_name) };
            let resp = rpc::RpcMessage::Fail(resp);
            resp.async_write(&mut stream).await?;

            return Ok(());
        }
    };

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

    let resp = rpc::RpcMessage::Ok(());
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

async fn serve(listener: TcpListener, accpt: Option<tokio_native_tls::TlsAcceptor>, state: SharedState) {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let accpt = accpt.map(Arc::new);

    loop {
        let (client, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(err) => {
                warn!("failed to accept(): {}", err);
                continue;
            }
        };
        let start = Instant::now();

        let state = state.clone();
        let accpt = accpt.clone();
        tokio::spawn(async move {
            let count = {
                COUNTER.fetch_add(1, Ordering::Relaxed) + 1
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

            let count = {
                COUNTER.fetch_sub(1, Ordering::Relaxed) - 1
            };
            debug!("connection with {:?} ended after {:?}; {} active connections", addr, start.elapsed(), count);
        });
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
        match Database::open(config.clone()).await {
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
    });

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

    if let Some(ref webcfg) = state.config.api_server {
        let bind_addr = webcfg.bind_addr;
        let state = state.clone();
        info!("starting http api server on {:?}", &bind_addr);
        rt.spawn(async move {
            web::start_webserver(bind_addr, state).await;
        });
    }

    let async_server = async {
        let server = match TcpListener::bind(state.config.lumina.bind_addr).await {
            Ok(v) => v,
            Err(err) => {
                error!("failed to bind server port: {}", err);
                exit(1);
            },
        };

        info!("listening on {:?} secure={}", server.local_addr().unwrap(), tls_acceptor.is_some());
    
        serve(server, tls_acceptor, state.clone()).await;
    };

    let ctrlc = tokio::signal::ctrl_c();

    let racey = async move {
        tokio::select! {
            _ = async_server => {
                error!("server decided to quit. this is impossible.");
            },
            _ = ctrlc => {
                info!("process was signaled. Shutting down...");
            },
        }
    };

    rt.block_on(racey);
}
