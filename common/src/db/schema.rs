use std::borrow::Cow;

use diesel::Insertable;

pub use super::schema_auto::*;

diesel::table! {
    func_ranks {
        id -> Int4,
        name -> Text,
        len -> Int4,
        db_id -> Int4,
        chksum -> Nullable<Bytea>,
        metadata -> Nullable<Bytea>,
        rank -> Nullable<Int4>,
        push_dt -> Nullable<Timestamptz>,
        update_dt -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(func_ranks -> dbs (id));

#[derive(Insertable)]
#[diesel(table_name = creds)]
pub struct Creds<'a> {
    pub username: &'a str,
    pub email: &'a str,

    pub passwd_salt: Option<Cow<'a, [u8]>>,
    pub passwd_iters: i32,
    pub passwd_hash: Option<Cow<'a, [u8]>>,

    pub is_admin: bool,
}
