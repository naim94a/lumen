CREATE TABLE creds (
    id SERIAL PRIMARY KEY,

    username VARCHAR(256) UNIQUE NOT NULL,
    email VARCHAR(256) UNIQUE NOT NULL,

    passwd_salt bytea,
    passwd_iters INTEGER NOT NULL DEFAULT 10000,
    passwd_hash bytea,

    last_active TIMESTAMPTZ,
    creation_dt TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,

    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE
);

ALTER TABLE users ADD COLUMN cred_id INTEGER REFERENCES creds(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX user_cred_idx ON users(lic_id,lic_data,hostname,cred_id) NULLS NOT DISTINCT;
DROP INDEX user_hn_null;
DROP INDEX user_rec;
