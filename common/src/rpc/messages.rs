use serde::{Deserialize, Serialize};
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

#[derive(Debug, Deserialize, Serialize, Clone)]
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

#[derive(Debug, Deserialize, Serialize)]
pub struct DelHistory<'a> {
    pub unk0: u32, // =0x08
    pub unk1: Cow<'a, [Cow<'a, str>]>,
    pub unk2: Cow<'a, [[u64; 2]]>,
    pub unk3: Cow<'a, [[u64; 2]]>,
    pub unk4: Cow<'a, [Cow<'a, str>]>,
    pub unk5: Cow<'a, [Cow<'a, str>]>,
    pub unk6: Cow<'a, [Cow<'a, str>]>,
    pub unk7: Cow<'a, [Cow<'a, str>]>,
    pub unk8: Cow<'a, [Cow<'a, [u8; 16]>]>,
    pub funcs: Cow<'a, [Cow<'a, [u8; 16]>]>,
    pub unk10: Cow<'a, [[u64; 2]]>,
    pub unk11: u64,
}

#[derive(Deserialize, Serialize)]
pub struct DelHistoryResult {
    pub deleted_mds: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HelloResult<'a> {
    pub id: Cow<'a, str>,
    pub username: Cow<'a, str>,
    pub email: Cow<'a, str>,
    pub lic_id: Cow<'a, str>,
    pub karma: u32,
    pub last_active: u64,
    pub features: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetFuncHistories<'a> {
    #[serde(borrow)]
    pub funcs: Cow<'a, [PullMetadataFunc<'a>]>,
    pub unk0: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FunctionHistory<'a> {
    pub unk0: u64,
    pub unk1: u64,
    pub name: Cow<'a, str>,
    pub metadata: Cow<'a, [u8]>,
    pub timestamp: u64,
    pub author_idx: u32,
    pub idb_path_idx: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FunctionHistories<'a> {
    #[serde(borrow)]
    pub log: Cow<'a, [FunctionHistory<'a>]>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetFuncHistoriesResult<'a> {
    pub status: Cow<'a, [u32]>,
    #[serde(borrow)]
    pub funcs: Cow<'a, [FunctionHistories<'a>]>,
    pub users: Cow<'a, [Cow<'a, str>]>,
    pub dbs: Cow<'a, [Cow<'a, str>]>,
}
