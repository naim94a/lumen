use std::collections::HashSet;

use serde::{Serialize, Deserialize};
use crate::rpc::de::from_slice;

#[derive(Serialize, Deserialize)]
pub struct MetadataChunk<'a> {
    code: u32,
    data: &'a [u8],
}

#[derive(Debug)]
pub enum FunctionMetadata<'a> {
    FunctionComment(FunctionComment<'a>),
    ByteComment(ByteComment<'a>),
    ExtraComment(ExtraComment<'a>),
}

#[derive(Debug)]
pub struct FunctionComment<'a> {
    pub is_repeatable: bool,
    pub comment: &'a str,
}

#[derive(Debug)]
pub struct ByteComment<'a> {
    pub is_repeatable: bool,
    pub offset: u32,
    pub comment: &'a str,
}

#[derive(Debug)]
pub struct ExtraComment<'a> {
    pub offset: u32,
    pub anterior: &'a str,
    pub posterior: &'a str,
}

impl<'a> FunctionMetadata<'a> {
    fn is_useful(&self) -> bool {
        // TODO: rewrite using regex with configurable library names
        match self {
            FunctionMetadata::ExtraComment(cmt) => {
                if cmt.anterior.starts_with("; Exported entry ") // offset=0
                {
                    return false;
                }
                if cmt.anterior.is_empty() && cmt.posterior.is_empty() {
                    return false;
                }
            },
            FunctionMetadata::FunctionComment(cmt) => {
                if cmt.comment == "Microsoft VisualC v14 64bit runtime"
                    || cmt.comment == "Microsoft VisualC 64bit universal runtime"
                {
                    return false;
                }
                if cmt.comment.is_empty() {
                    return false;
                }
            },
            FunctionMetadata::ByteComment(cmt) => {
                if cmt.comment == "Trap to Debugger"
                    || (cmt.comment.starts_with("jumptable ") && cmt.comment.contains(" case")) // repeatable=true
                    || cmt.comment == "switch jump"
                    || (cmt.comment.starts_with("switch ") && cmt.comment.ends_with(" cases "))
                    || cmt.comment == "jump table for switch statement"
                    || cmt.comment == "indirect table for switch statement"
                    || cmt.comment == "Microsoft VisualC v7/14 64bit runtime"
                    || cmt.comment == "Microsoft VisualC v7/14 64bit runtime\nMicrosoft VisualC v14 64bit runtime"
                    || cmt.comment == "Microsoft VisualC v14 64bit runtime" {
                        return false;
                }
                if cmt.comment.is_empty() {
                    return false;
                }
            },
        }
        true
    }
}

fn deserialize_seq<'de, T: Deserialize<'de>>(mut data: &'de [u8]) -> Result<Vec<(u32, T)>, crate::rpc::Error> {
    let mut res = vec![];
    let mut reset = true;
    let (mut offset, used): (u32, usize) = from_slice(data)?;
    data = &data[used..];
    if data.is_empty() {
        return Err(crate::rpc::Error::UnexpectedEof);
    }

    loop {
        let (offset_diff, used): (u32, usize) = from_slice(data)?;
        data = &data[used..];
        if data.is_empty() {
            return Err(crate::rpc::Error::UnexpectedEof);
        }
        
        if (offset_diff > 0) || reset {
            offset += offset_diff;
            let (e, used): (T, usize) = from_slice(data)?;
            data = &data[used..];

            res.push((offset, e));

            reset = false;
        } else {
            let (offset_diff, used): (u32, usize) = from_slice(data)?;
            data = &data[used..];

            offset = offset_diff;
            reset = true;
        }

        if data.is_empty() {
            break;
        }
    }

    Ok(res)
}

pub fn parse_metadata(mut data: &[u8]) -> Result<Vec<FunctionMetadata<'_>>, crate::rpc::Error> {
    let mut res = vec![];
    let mut bad_codes = HashSet::new();

    while !data.is_empty() {
        let (chunk, used) :(MetadataChunk, _) = from_slice(data)?;
        data = &data[used..];

        let data = chunk.data;

        if data.is_empty() {
            continue;
        }

        match chunk.code {
            1 => {}, // TODO: parse typeinfo
            2 => {}, // nop
            3 | 4 => { // function comments
                let is_repeatable = chunk.code == 4;
                let cmt = std::str::from_utf8(data)?;
                res.push(FunctionMetadata::FunctionComment(FunctionComment{
                    is_repeatable,
                    comment: cmt,
                }));
            },
            5 | 6 => { // comments
                let is_repeatable = chunk.code == 6;
                let byte_comments: Vec<(_, &[u8])> = match deserialize_seq(data) {
                    Ok(v) => v,
                    Err(err) => {
                        log::error!("err: {}\n{}", err, super::make_pretty_hex(data));
                        return Err(err);
                    },
                };
                
                for comment in byte_comments {
                    let cmt = std::str::from_utf8(comment.1)?;
                    res.push(FunctionMetadata::ByteComment(
                        ByteComment{
                            is_repeatable,
                            offset: comment.0,
                            comment: cmt,
                        }
                    ));
                }
            },
            7 => { // extra comments
                let byte_comments: Vec<(_, (&[u8], &[u8]))> = match deserialize_seq(data) {
                    Ok(v) => v,
                    Err(err) => {
                        log::error!("err: {}\n{}", err, super::make_pretty_hex(data));
                        return Err(err);
                    },
                };
                
                for comment in byte_comments {
                    res.push(FunctionMetadata::ExtraComment(ExtraComment{
                        offset: comment.0,
                        anterior: std::str::from_utf8(comment.1.0)?,
                        posterior: std::str::from_utf8(comment.1.1)?,
                    }));
                }
            },
            9 | 10 => { /* TODO! */ },
            _ => {
                bad_codes.insert(chunk.code);
            },
        }
    }

    Ok(res)
}

pub fn get_score(md: &crate::rpc::PushMetadataFunc) -> u32 {
    let mut score = 0;

    let md = match parse_metadata(md.func_data) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("failed to parse metadata: {}", e);
            return 0;
        }
    };

    for md in md {
        if md.is_useful() {
            score += 10;
        }
    }

    score
}
