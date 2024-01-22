use std::process::exit;

use common::{config::Config, db::Database};

pub struct UserMgmt(Database);

impl UserMgmt {
    pub async fn new(cfg: &Config) -> Self {
        let db = match Database::open(&cfg.database).await {
            Ok(v) => v,
            Err(err) => {
                eprintln!("failed to open database: {}", err);
                exit(1);
            },
        };

        Self(db)
    }

    pub async fn list_users(&self) {
        let users = self.0.get_users().await.expect("failed to retreive users from database");
        println!("{users:?}");
    }

    pub async fn set_password(&self, username: &str, password: &str) {
        self.0.set_password(username, password).await.expect("failed to set user's password")
    }

    pub async fn add_user(&self, username: &str, email: &str, is_admin: bool) {
        let id = self.0.add_user(username, email, is_admin).await.expect("failed to add user");
        println!("{username}'s id is {id}.")
    }

    pub async fn delete_user(&self, username: &str) {
        self.0.delete_user(username).await.expect("failed to delete user");
    }
}
