CREATE TABLE creds (
    id SERIAL PRIMARY KEY,

    username VARCHAR(256) UNIQUE NOT NULL,
    email VARCHAR(256) UNIQUE NOT NULL,

    passwd_salt bytea,
    passwd_iters INTEGER NOT NULL DEFAULT 10000,
    passwd_hash bytea,

    is_admin BOOLEAN NOT NULL DEFAULT FALSE
);
