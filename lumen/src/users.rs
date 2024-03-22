use std::process::exit;

use common::{config::Config, db::Database};

pub struct UserMgmt {
    db: Database,
    pbkd2_iters: u32,
}

impl UserMgmt {
    pub async fn new(cfg: &Config) -> Self {
        let db = match Database::open(&cfg.database).await {
            Ok(v) => v,
            Err(err) => {
                eprintln!("failed to open database: {}", err);
                exit(1);
            },
        };

        Self { db, pbkd2_iters: cfg.users.pbkdf2_iterations.get() }
    }

    pub async fn list_users(&self) {
        let users = self.db.get_users().await.expect("failed to retreive users from database");
        println!("{users:?}");
    }

    pub async fn set_password(&self, username: &str, password: &str) {
        self.db
            .set_password(username, password.to_owned(), self.pbkd2_iters)
            .await
            .expect("failed to set user's password")
    }

    pub async fn add_user(&self, username: &str, email: &str, is_admin: bool) {
        let id = self.db.add_user(username, email, is_admin).await.expect("failed to add user");
        println!("{username}'s id is {id}.")
    }

    pub async fn delete_user(&self, username: &str) {
        self.db.delete_user(username).await.expect("failed to delete user");
    }
}
