#![forbid(unsafe_code)]
#![warn(unused_crate_dependencies)]
#![feature(try_reserve)]

use std::fmt::Write;

pub mod db;
pub mod config;
pub mod md;
pub mod rpc;
pub mod web;

pub struct SharedState_ {
    pub db: db::Database,
    pub config: std::sync::Arc<config::Config>,
}

pub type SharedState = std::sync::Arc<SharedState_>;

pub fn make_pretty_hex(data: &[u8]) -> String {
    let mut output = String::new();
    const CHUNK_SIZE: usize = 32;
    data.chunks(CHUNK_SIZE).for_each(|chunk| {
        for &ch in chunk {
            let _ = write!(&mut output, "{:02x} ", ch);
        }
        let padding = CHUNK_SIZE - chunk.len();
        for _ in 0..padding {
            let _ = write!(&mut output, ".. ");
        }

        let _ = write!(&mut output, " | ");
        for ch in chunk.iter().chain(std::iter::repeat(&b' ').take(padding)).map(|&v| std::char::from_u32(v as u32).unwrap_or('.')) {
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
