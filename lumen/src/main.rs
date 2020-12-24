// Copyright (C) 2020 Naim A. <naim@abda.nl>

#![forbid(unsafe_code)]
#![warn(unused_crate_dependencies)]

use native_tls::Identity;
use clap::{Arg, App};
use log::*;
use std::{borrow::Cow, sync::Arc};
use tokio::{net::TcpListener, io::AsyncWrite, io::AsyncRead};
use std::process::exit;
use common::{SharedState, SharedState_};

mod web;

use common::{config, db, make_pretty_hex, md, rpc::{self, Error}};
use common::db::Database;
use rpc::RpcMessage;

fn setup_logger() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", concat!(env!("CARGO_PKG_NAME"), "=info"));
    }
    pretty_env_logger::init_timed();
}


async fn handle_client<S: AsyncRead + AsyncWrite + Unpin>(db: &db::Database, mut stream: S) -> Result<(), rpc::Error> {
    let hello = rpc::read_packet(&mut stream).await?;
    
    let hello = match RpcMessage::deserialize(&hello) {
        Ok(RpcMessage::Hello(v)) => v,
        _ => {
            // send error
            error!("got bad hello message");

            let resp = rpc::RpcFail{ code: 0, message: "lumen.abda.nl: bad sequence.\n" };
            let resp = rpc::RpcMessage::Fail(resp);
            resp.async_write(&mut stream).await?;

            return Ok(());
        }
    };

    let resp = rpc::RpcMessage::Ok(());
    resp.async_write(&mut stream).await?;

    'server: loop {
        trace!("waiting for command..");
        let req = match rpc::read_packet(&mut stream).await {
            Ok(v) => v,
            Err(Error::IOError(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        trace!("got command!");
        let req = match RpcMessage::deserialize(&req) {
            Ok(v) => v,
            Err(err) => {
                trace!("bad message: \n{}\n", make_pretty_hex(&req));
                error!("failed to process rpc message: {}", err);
                let resp = rpc::RpcFail{ code: 0, message: "lumen.abda.nl: error: invalid data\n" };
                let resp = RpcMessage::Fail(resp);
                resp.async_write(&mut stream).await?;

                return Ok(());
            },
        };
        match req {
            RpcMessage::PullMetadata(md) => {
                let funcs = match db.get_funcs(&md.funcs).await {
                    Ok(v) => v,
                    Err(e) => {
                        error!("pull failed, db: {}", e);
                        rpc::RpcMessage::Fail(rpc::RpcFail {
                            code: 0,
                            message: "lumen.abda.nl: db error; please try again later."
                        }).async_write(&mut stream).await?;
                        continue 'server;
                    },
                };

                let statuses: Vec<u32> = funcs.iter().map(|v| if v.is_none() { 1 } else {0}).collect();
                let found = funcs
                    .into_iter()
                    .filter_map(|v| v)
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
                let scores: Vec<u32> = mds.funcs.iter()
                    .map(md::get_score)
                    .collect();

                let status = match db.push_funcs(&hello, &mds, &scores).await {
                    Ok(v) => {
                        v.into_iter().map(|v| if v {1} else {0}).collect::<Vec<u32>>()
                    },
                    Err(err) => {
                        log::error!("push failed, db: {}", err);
                        rpc::RpcMessage::Fail(rpc::RpcFail {
                            code: 0,
                            message: "lumen.abda.nl: db error; please try again later."
                        }).async_write(&mut stream).await?;
                        continue 'server;
                    }
                };

                RpcMessage::PushMetadataResult(rpc::PushMetadataResult {
                    status: Cow::Owned(status),
                }).async_write(&mut stream).await?;
            },
            _ => {
                RpcMessage::Fail(rpc::RpcFail{code: 0, message: "lumen.abda.nl: invalid data\n"}).async_write(&mut stream).await?;
            }
        }
    }
}

async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(state: &SharedState, s: S) {
    if let Err(err) = handle_client(&state.db, s).await {
        warn!("err: {}", err);
    }
}

async fn serve(listener: TcpListener, accpt: Option<tokio_native_tls::TlsAcceptor>, state: SharedState) {
    let accpt = accpt.map(Arc::new);
    loop {
        let (client, addr) = match listener.accept().await {
            Ok(v) => v,
            Err(err) => {
                warn!("failed to accept(): {}", err);
                continue;
            }
        };

        let counter = std::sync::atomic::AtomicU32::new(0);

        let state = state.clone();
        let accpt = accpt.clone();
        tokio::spawn(async move {
            let count = {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
            };
            let protocol = if accpt.is_some() {" [TLS]"} else {""};
            debug!("Connection from {:?}{}: {} active connections", &addr, protocol, count);
            match accpt {
                Some(accpt) => {
                    match accpt.accept(client).await {
                        Ok(s) => {
                            handle_connection(&state, s).await;
                        },
                        Err(err) => error!("tls accept ({}): {}", &addr, err),
                    };
                },
                None => handle_connection(&state, client).await,
            }

            let count = {
                counter.fetch_sub(1, std::sync::atomic::Ordering::Relaxed) - 1
            };
            debug!("connection with {:?} ended; {} active connections", addr, count);
        });
    }
}

async fn maintenance(state: std::sync::Weak<SharedState_>) {
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(10));

    loop {
        timer.tick().await;

        if let Some(state) = state.upgrade() {
            
            if !state.db.is_online().await {
                warn!("db is offline; attempting to reconnect...");
                match state.db.reconnect().await {
                    Ok(_) => info!("reconnected."),
                    Err(err) => error!("failed to reconnect: {}", err),
                }
            }

        } else {
            warn!("shared state is not available");
            break;
        }
    }
}

fn main() {
    setup_logger();
    let matches = App::new("lumen")
        .version(env!("CARGO_PKG_VERSION"))
        .about("lumen is a private Lumina server for IDA.\nVisit https://github.com/naim94a/lumen/ for updates.")
        .author("Naim A. <naim@abda.nl>")
        .arg(
            Arg::with_name("config")
                .short("c")
                .takes_value(true)
                .required(true)
                .default_value("config.toml")
                .help("Configuration file path")
        )
        .get_matches();

    let config = {
        config::load_config(std::fs::File::open(matches.value_of("config").unwrap()).expect("failed to read config"))
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
    
    let state = Arc::new(SharedState_{
        db,
        config,
    });

    rt.spawn(maintenance(Arc::downgrade(&state)));

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
        // workaround until warp supports tokio 0.3
        let mut rt2 = tokio2::runtime::Builder::new()
            .enable_all()
            .threaded_scheduler()
            .build()
            .expect("failed to build tokio2 rt");
        let bind_addr = webcfg.bind_addr;
        let state = state.clone();
        info!("starting http api server on {:?}", &bind_addr);
        std::thread::spawn(move || {
            rt2.block_on(async move {
                web::start_webserver(bind_addr, state).await;
            });
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
