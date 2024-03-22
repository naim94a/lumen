use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Deserialize, Serialize)]
pub struct RpcFail<'a> {
    pub result: u32,
    pub error: &'a str,
}

#[derive(Serialize, Deserialize)]
pub struct RpcNotify<'a> {
    pub ty: u32,
    pub text: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Creds<'a> {
    pub username: &'a str,
    pub password: &'a str,
}

#[derive(Serialize, Deserialize)]
pub struct RpcHello<'a> {
    pub client_version: u32,
    pub license_data: &'a [u8],
    pub lic_number: [u8; 6],
    pub record_conv: u32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PatternId<'a> {
    pub ty: u32,
    pub data: &'a [u8],
}

#[derive(Deserialize, Serialize)]
pub struct PullMetadata<'a> {
    pub flags: u32,
    pub keys: Cow<'a, [u32]>,

    #[serde(borrow)]
    pub pattern_ids: Cow<'a, [PatternId<'a>]>,
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
    pub codes: Cow<'a, [u32]>,
    #[serde(borrow)]
    pub funcs: Cow<'a, [PullMetadataResultFunc<'a>]>,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct PushMetadataFunc<'a> {
    pub name: &'a str,
    pub func_len: u32,
    pub func_data: &'a [u8],
    pub pattern_id: PatternId<'a>,
}

#[derive(Deserialize, Serialize)]
pub struct PushMetadata<'a> {
    pub flags: u32,
    pub idb_path: &'a str,
    pub input_path: &'a str,
    pub input_md5: [u8; 16],
    pub hostname: &'a str,
    pub funcs: Cow<'a, [PushMetadataFunc<'a>]>,
    pub ea64s: Cow<'a, [u64]>,
}

#[derive(Deserialize, Serialize)]
pub struct PushMetadataResult<'a> {
    // array of 0=exists, 1=NEW
    pub status: Cow<'a, [u32]>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DelHistory<'a> {
    pub flags: u32, // =0x08
    pub license_ids: Cow<'a, [Cow<'a, str>]>,
    pub time_ranges: Cow<'a, [[u64; 2]]>,
    pub history_id_ranges: Cow<'a, [[u64; 2]]>,
    pub idbs: Cow<'a, [Cow<'a, str>]>,
    pub inputs: Cow<'a, [Cow<'a, str>]>,
    pub funcs: Cow<'a, [Cow<'a, str>]>, // funcs
    pub usernames: Cow<'a, [Cow<'a, str>]>,
    pub input_hashes: Cow<'a, [Cow<'a, [u8; 16]>]>,
    pub calcrel_hashes: Cow<'a, [Cow<'a, [u8; 16]>]>,
    pub push_id_ranges: Cow<'a, [[u64; 2]]>,
    pub max_entries: u64,
}

#[derive(Deserialize, Serialize)]
pub struct DelHistoryResult {
    pub ndeleted: u32,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct LicenseInfo<'a> {
    pub id: Cow<'a, str>,
    pub name: Cow<'a, str>,
    pub email: Cow<'a, str>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct HelloResult<'a> {
    pub license_info: LicenseInfo<'a>,
    pub username: Cow<'a, str>,
    pub karma: u32,
    pub last_active: u64,
    pub features: u32,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetFuncHistories<'a> {
    #[serde(borrow)]
    pub funcs: Cow<'a, [PatternId<'a>]>,
    pub flags: u32,
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
    pub authors: Cow<'a, [Cow<'a, str>]>,
    pub idb_paths: Cow<'a, [Cow<'a, str>]>,
}
