#![forbid(unsafe_code)]
#![warn(unused_crate_dependencies)]

use std::fmt::Write;

pub mod async_drop;
pub mod config;
pub mod db;
pub mod md;
pub mod metrics;
pub mod rpc;
pub mod web;

pub struct SharedState_ {
    pub db: db::Database,
    pub config: std::sync::Arc<config::Config>,
    pub server_name: String,
    pub metrics: metrics::Metrics,
}

pub type SharedState = std::sync::Arc<SharedState_>;

pub fn make_pretty_hex(data: &[u8]) -> String {
    let mut output = String::new();
    const CHUNK_SIZE: usize = 32;
    data.chunks(CHUNK_SIZE).for_each(|chunk| {
        for &ch in chunk {
            let _ = write!(&mut output, "{ch:02x} ");
        }
        let padding = CHUNK_SIZE - chunk.len();
        for _ in 0..padding {
            let _ = write!(&mut output, ".. ");
        }

        let _ = write!(&mut output, " | ");
        for ch in chunk
            .iter()
            .chain(std::iter::repeat(&b' ').take(padding))
            .map(|&v| std::char::from_u32(v as u32).unwrap_or('.'))
        {
            if !ch.is_ascii_graphic() {
                output.push('.');
            } else {
                output.push(ch);
            }
        }
        output.push_str(" |\n");
    });

    output
}
