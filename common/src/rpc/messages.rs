use serde::{Serialize, Deserialize};
use std::borrow::Cow;

#[derive(Deserialize, Serialize)]
pub struct RpcFail<'a> {
    pub code: u32,
    pub message: &'a str,
}

#[derive(Serialize, Deserialize)]
pub struct RpcNotify<'a> {
    pub code: u32,
    pub msg: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Creds<'a> {
    pub username: &'a str,
    pub password: &'a str,
}

#[derive(Serialize, Deserialize)]
pub struct RpcHello<'a> {
    pub protocol_version: u32,
    pub license_data: &'a [u8],
    pub lic_number: [u8; 6],
    pub unk2: u32,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct PullMetadataFunc<'a> {
    pub unk0: u32,
    pub mb_hash: &'a [u8],
}

#[derive(Deserialize, Serialize)]
pub struct PullMetadata<'a> {
    pub unk0: u32,
    pub unk1: Cow<'a, [u32]>,

    #[serde(borrow)]
    pub funcs: Cow<'a, [PullMetadataFunc<'a>]>,
}

#[derive(Deserialize, Serialize, Clone)]
pub struct PullMetadataResultFunc<'a> {
    pub name: Cow<'a, str>,
    pub len: u32,
    pub mb_data: Cow<'a, [u8]>,
    pub popularity: u32,
}

#[derive(Deserialize, Serialize)]
pub struct PullMetadataResult<'a> {
    pub unk0: Cow<'a, [u32]>,
    #[serde(borrow)]
    pub funcs: Cow<'a, [PullMetadataResultFunc<'a>]>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PushMetadataFunc<'a> {
    pub name: &'a str,
    pub func_len: u32,
    pub func_data: &'a [u8],

    // PullMetadata's fields (tuple 'unk2') are similar to these two
    pub unk2: u32,
    pub hash: &'a [u8],
}

#[derive(Deserialize, Serialize)]
pub struct PushMetadata<'a> {
    pub unk0: u32,
    pub idb_path: &'a str,
    pub file_path: &'a str,
    pub md5: [u8; 16],
    pub hostname: &'a str,
    pub funcs: Cow<'a, [PushMetadataFunc<'a>]>,
    pub unk1: Cow<'a, [u64]>,
}

#[derive(Deserialize, Serialize)]
pub struct PushMetadataResult<'a> {
    // array of 0=exists, 1=NEW
    pub status: Cow<'a, [u32]>,
}
