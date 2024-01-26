use std::borrow::Cow;

use diesel::{Insertable, Queryable, Selectable};
use log::error;
use pbkdf2::{hmac::Hmac, pbkdf2};
use sha2::Sha256;

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

#[derive(Insertable, Queryable, Selectable)]
#[diesel(table_name = creds)]
pub struct Creds<'a> {
    pub username: Cow<'a, str>,
    pub email: Cow<'a, str>,

    pub passwd_salt: Option<Cow<'a, [u8]>>,
    pub passwd_iters: i32,
    pub passwd_hash: Option<Cow<'a, [u8]>>,

    pub is_admin: bool,
}

impl<'a> Creds<'a> {
    pub fn verify_password(&self, password: &str) -> bool {
        let salt = if let Some(v) = self.passwd_salt.as_ref() {
            v
        } else {
            return false;
        };
        let current_hash = if let Some(v) = self.passwd_hash.as_ref() {
            v
        } else {
            return false;
        };
        if self.passwd_iters == 0 {
            return false;
        }

        let mut hash = vec![0u8; 32];
        if pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, self.passwd_iters as u32, &mut hash)
            .is_err()
        {
            error!("invalid output digest length");
            return false;
        }

        hash == current_hash.as_ref()
    }
}
