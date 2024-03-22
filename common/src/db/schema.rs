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

#[derive(Insertable, Queryable, Selectable, Default)]
#[diesel(table_name = creds)]
pub struct Creds<'a> {
    pub username: Cow<'a, str>,
    pub email: Cow<'a, str>,

    pub passwd_salt: Option<Cow<'a, [u8]>>,
    pub passwd_iters: i32,
    pub passwd_hash: Option<Cow<'a, [u8]>>,

    pub last_active: Option<time::OffsetDateTime>,

    pub is_admin: bool,
    pub is_enabled: bool,
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
        if self.passwd_iters <= 0 {
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

    pub(crate) fn generate_creds(password: &str, iters: u32) -> ([u8; 4], [u8; 32]) {
        let salt: [u8; 4] = rand::random();
        let mut res = [0u8; 32];
        pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, iters, &mut res)
            .expect("failed to perform pbkdf2_hmac_sha256");
        (salt, res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify_password() {
        let password = "MyPassword1$";
        let iters = 10_000;
        let (salt, hash) = Creds::generate_creds(password, iters);
        let creds = Creds {
            passwd_hash: Some((&hash[..]).into()),
            passwd_salt: Some((&salt[..]).into()),
            passwd_iters: iters as i32,
            ..Default::default()
        };
        assert!(creds.verify_password(password), "failed to verify password");
    }
}
