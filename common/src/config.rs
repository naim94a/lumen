use serde::Deserialize;
use std::num::NonZeroU32;
use std::time::Duration;
use std::{net::SocketAddr, path::PathBuf};
use toml::from_str;

#[derive(Deserialize)]
pub struct TlsIdentity {
    pub server_cert: PathBuf,
}

#[derive(Deserialize)]
#[serde(default)]
pub struct LuminaServer {
    pub bind_addr: SocketAddr,
    pub use_tls: bool,
    pub tls: Option<TlsIdentity>,
    pub server_name: Option<String>,
    pub allow_deletes: bool,

    /// limit of function histories to return per function.
    /// `None`, or `Some(0)` will disable the feature on the server.
    pub get_history_limit: NonZeroU32,
}
impl Default for LuminaServer {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:1234".parse().unwrap(),
            use_tls: false,
            tls: None,
            server_name: None,
            allow_deletes: false,
            get_history_limit: NonZeroU32::new(50).unwrap(),
        }
    }
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

#[derive(Deserialize, Debug)]
#[serde(default)]
pub struct Limits {
    /// Maximum time to wait on an idle connection between commands.
    pub command_timeout: Duration,

    /// Maximum time to all `PULL_MD` queries.
    pub pull_md_timeout: Duration,

    /// Maximum time to wait for `HELO` message.
    pub hello_timeout: Duration,

    /// Maximum time allowed until TLS handshake completes.
    pub tls_handshake_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            command_timeout: Duration::from_secs(3600),
            pull_md_timeout: Duration::from_secs(4 * 60),
            hello_timeout: Duration::from_secs(15),
            tls_handshake_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Deserialize)]
#[serde(default)]
pub struct Users {
    /// Sets if guests are allowed to login. required for IDA<8.1
    pub allow_guests: bool,

    /// PBKDF2 iterations for newly set passwords.
    pub pbkdf2_iterations: NonZeroU32,
}

impl Default for Users {
    fn default() -> Self {
        Self { allow_guests: true, pbkdf2_iterations: NonZeroU32::new(120_000).unwrap() }
    }
}

#[derive(Deserialize)]
pub struct Config {
    pub lumina: LuminaServer,
    pub api_server: Option<WebServer>,
    pub database: Database,

    #[serde(default)]
    pub limits: Limits,

    #[serde(default)]
    pub users: Users,
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
