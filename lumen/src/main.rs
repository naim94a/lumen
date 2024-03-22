// Copyright (C) 2022 Naim A. <naim@abda.nl>

#![forbid(unsafe_code)]
#![warn(unused_crate_dependencies)]
#![deny(clippy::all)]

use clap::{builder::BoolishValueParser, Arg, Command};
use log::*;
use server::do_lumen;
use std::sync::Arc;
use users::UserMgmt;

mod server;
mod users;
mod web;

fn setup_logger() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", concat!(env!("CARGO_PKG_NAME"), "=info"));
    }
    pretty_env_logger::init_timed();
}

#[tokio::main]
async fn main() {
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
        .subcommand(
            Command::new("users")
                .about("User Management")
                .subcommand(
                    Command::new("add")
                        .about("Adds a user")
                        .arg(
                            Arg::new("username")
                                .required(true)
                        )
                        .arg(
                            Arg::new("email")
                                .required(true)
                        )
                        .arg(
                            Arg::new("is_admin")
                                .required(false)
                                .default_value("no")
                                .value_parser(BoolishValueParser::new())
                        )
                )
                .subcommand(
                    Command::new("del")
                        .about("Deletes a user")
                        .arg(Arg::new("username"))
                )
        )
        .subcommand(Command::new("passwd").about("Set user password").arg(Arg::new("username").required(true)))
        .get_matches();

    let config = {
        common::config::load_config(
            std::fs::File::open(matches.get_one::<String>("config").unwrap())
                .expect("failed to read config"),
        )
    };
    let config = Arc::new(config);

    match matches.subcommand() {
        Some(("users", m)) => {
            let users = UserMgmt::new(&config).await;
            match m.subcommand() {
                None => users.list_users().await,
                Some(("add", m)) => {
                    let username = m.get_one::<String>("username").unwrap();
                    let email = m.get_one::<String>("email").unwrap();
                    let is_admin = *m.get_one::<bool>("is_admin").unwrap_or(&false);
                    users.add_user(username, email, is_admin).await;
                },
                Some(("del", m)) => {
                    let username = m.get_one::<String>("username").unwrap();
                    users.delete_user(username).await;
                },
                _ => unreachable!(),
            };
        },
        Some(("passwd", m)) => {
            let username = m.get_one::<String>("username").unwrap();
            let password = rpassword::prompt_password("New Password: ").unwrap();
            let users = UserMgmt::new(&config).await;
            users.set_password(username, &password).await;
        },
        Some(_) => unreachable!(),
        None => {
            setup_logger();
            do_lumen(config).await
        },
    };
}
