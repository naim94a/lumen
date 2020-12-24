use std::borrow::Cow;
use log::*;
use warp::{Filter, Reply, Rejection};
use crate::{db::DbStats};
use serde::Serialize;

use super::SharedState;

struct Md5([u8; 16]);
impl std::str::FromStr for Md5 {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Md5, Self::Err> {
        let mut res = [0u8; 16];
        let s = s.trim();
        if s.len() != 32 {
            return Err("bad md5 length");
        }
        binascii::hex2bin(s.as_bytes(), &mut res)
            .map_err(|_| "bad md5")?;
        Ok(Md5(res))
    }
}

#[derive(Serialize)]
struct Error<'a> {
    error: &'a str,
}

impl std::fmt::Display for Md5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = [0u8; 32];
        binascii::bin2hex(&self.0, &mut out).unwrap();
        let out = std::str::from_utf8(&out).unwrap();
        write!(f, "{}", &out)
    }
}

impl Serialize for Md5 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{}", &self))
    }
}

pub fn api_root(state: SharedState) -> impl Filter<Extract = (impl Reply + 'static, ), Error=Rejection> + Clone {
    let view_file = warp::get()
        .and(warp::path("files"))
        .and(super::with_state(state.clone()))
        .and(warp::filters::path::param::<Md5>())
        .and_then(view_file_by_hash);
    let view_func = warp::get()
        .and(warp::path("funcs"))
        .and(super::with_state(state.clone()))
        .and(warp::filters::path::param::<Md5>())
        .and_then(view_func_by_hash);
    let view_status = warp::get()
        .and(warp::path("status"))
        .and(super::with_state(state.clone()))
        .and_then(view_status);

    view_file
        .or(view_func)
        .or(view_status)
}

// GET server/api/files/:md5
async fn view_file_by_hash(state: SharedState, md5: Md5) -> Result<impl Reply, Rejection> {
    #[derive(Serialize)]
    struct FileFunc {
        hash: Md5,
        len: u32,
        name: String,
    }

    let v = match state.db.get_file_funcs(&md5.0[..], 0, 10_000).await {
        Ok(v) => v,
        Err(err) => {
            error!("failed to get file's funcs {}: {}", &md5, err);
            return Ok(warp::reply::json(&Error{error: "internal server error"}));
        },
    };
    let v: Vec<_> = v.into_iter()
        .map(|v| {
            FileFunc {
                name: v.0,
                len: v.1,
                hash: Md5(v.2),
            }
        })
        .collect();

    Result::<_, Rejection>::Ok(warp::reply::json(&v))
}

// GET server/api/funcs/:md5
async fn view_func_by_hash(state: SharedState, md5: Md5) -> Result<impl Reply, Rejection> {
    #[derive(Serialize)]
    enum CommentType {
        Posterior,
        Anterior,
        Function{ repeatable: bool },
        Byte { repeatable: bool },
    }

    #[derive(Serialize)]
    struct Comment<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<u32>,
        #[serde(rename = "type")]
        type_: CommentType,
        comment: Cow<'a, str>,
    }

    #[derive(Serialize)]
    struct FuncInfo<'a> {
        name: &'a str,
        comments: Vec<Comment<'a>>,
        length: u32,
        in_files: &'a [Md5],
    }

    let funcs = [crate::rpc::PullMetadataFunc {
        unk0: 1,
        mb_hash: &md5.0
    }];

    let files_with = state.db.get_files_with_func(&md5.0[..]);
    let files_info =  state.db.get_funcs(&funcs);

    let (files_with, files_info) = match futures_util::try_join!(files_with, files_info) {
        Ok(v) => v,
        Err(err) => {
            error!("failed to execute db queries: {}", err);
            return Ok(warp::reply::json(&Error {error: "internal server error"}));
        }
    };

    let files_with: Vec<Md5> = files_with.into_iter().map(Md5).collect();

    let v = files_info;
    let v: Vec<FuncInfo> = v
        .iter()
        .take(1)
        .filter_map(|v| v.as_ref())
        .filter_map(|v| {
            let md = match crate::md::parse_metadata(&v.data) {
                Ok(v) => v,
                Err(e) => {
                    error!("error parsing metadata for {}: {}", &md5, e);
                    return None;
                }
            };
            let comments: Vec<Comment> = md.into_iter()
                .filter_map(|md| {
                    match md {
                        crate::md::FunctionMetadata::ByteComment(c) => {
                            Some(vec![Comment {
                                offset: Some(c.offset),
                                type_: CommentType::Byte{ repeatable: c.is_repeatable },
                                comment: c.comment.into(),
                            }])
                        },
                        crate::md::FunctionMetadata::FunctionComment(c) => {
                            Some(vec![Comment {
                                offset: None,
                                type_: CommentType::Function{ repeatable: c.is_repeatable },
                                comment: c.comment.into(),
                            }])
                        },
                        crate::md::FunctionMetadata::ExtraComment(c) => {
                            let mut res = vec![];
                            if !c.anterior.is_empty() {
                                res.push(Comment {
                                    offset: Some(c.offset),
                                    type_: CommentType::Anterior,
                                    comment: c.anterior.into(),
                                });
                            }
                            if !c.posterior.is_empty() {
                                res.push(Comment {
                                    offset: Some(c.offset),
                                    type_: CommentType::Posterior,
                                    comment: c.posterior.into(),
                                });
                            }
                            if !res.is_empty() {
                                Some(res)
                            } else {
                                None
                            }
                        },
                    }
                })
                .flatten()
                .collect();
            Some(FuncInfo {
                name: &v.name,
                length: v.len,
                comments,
                in_files: &files_with,
            })
        }).collect();

    Result::<_, Rejection>::Ok(warp::reply::json(&v))
}

// GET /api/status
async fn view_status(state: SharedState) -> Result<impl Reply, Rejection> {
    #[derive(Serialize)]
    enum DbStatus {
        Stats(DbStats),
        Error(String),
    }

    #[derive(Serialize)]
    struct Response {
        db_online: bool,
        stats: DbStatus,
    }

    let stats = match state.db.get_stats().await {
        Ok(stats) => DbStatus::Stats(stats),
        Err(err) => DbStatus::Error(format!("{}", err)),
    };

    Result::<_, Rejection>::Ok(warp::reply::json(&Response {
        db_online: state.db.is_online().await,
        stats,
    }))
}