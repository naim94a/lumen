// Copyright (C) 2022 Naim A. <naim@abda.nl>

#![forbid(unsafe_code)]
#![warn(unused_crate_dependencies)]
#![deny(clippy::all)]

use clap::Arg;

use server::do_lumen;
use std::sync::Arc;

mod server;
mod web;

use common::config;

fn setup_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lumen=info,common=info".into()),
        )
        .init();
}

#[tokio::main]
async fn main() {
    setup_tracing();
    let matches = clap::Command::new("lumen")
        .version(env!("CARGO_PKG_VERSION"))
        .about("lumen is a private Lumina server for IDA.\nVisit https://github.com/naim94a/lumen/ for updates.")
        .author("Naim A. <naim@abda.nl>")
        .arg(
            Arg::new("config")
                .short('c')
                .default_value("config.toml")
                .help("Configuration file path")
        )
        .get_matches();

    let config = {
        config::load_config(
            std::fs::File::open(matches.get_one::<String>("config").unwrap())
                .expect("failed to read config"),
        )
    };
    let config = Arc::new(config);

    do_lumen(config).await;
}
