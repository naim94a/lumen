use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};
use toml::from_str;

#[derive(Deserialize)]
pub struct TlsIdentity {
    pub server_cert: PathBuf,
}

#[derive(Deserialize)]
pub struct LuminaServer {
    pub bind_addr: SocketAddr,
    pub use_tls: Option<bool>,
    pub tls: Option<TlsIdentity>,
    pub server_name: Option<String>,
    pub allow_deletes: Option<bool>,

    /// limit of function histories to return per function.
    /// `None`, or `Some(0)` will disable the feature on the server.
    pub get_history_limit: Option<u32>,
}

#[derive(Deserialize)]
pub struct WebServer {
    pub bind_addr: SocketAddr,
}

#[derive(Deserialize)]
pub struct Database {
    pub connection_info: String,

    pub use_tls: bool,
    pub server_ca: Option<PathBuf>,
    pub client_id: Option<PathBuf>,
}

#[derive(Deserialize)]
pub struct Config {
    pub lumina: LuminaServer,
    pub api_server: Option<WebServer>,
    pub database: Database,
}

pub trait HasConfig {
    fn get_config(&self) -> &Config;
}

impl HasConfig for Config {
    fn get_config(&self) -> &Config {
        self
    }
}

pub fn load_config<R: std::io::Read>(mut fd: R) -> Config {
    let mut buf = vec![];
    fd.read_to_end(&mut buf).expect("failed to read config");

    let buf = std::str::from_utf8(&buf).expect("file contains invalid utf-8");

    from_str(buf).expect("failed to parse configuration")
}
