CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    lic_id bytea,
    lic_data bytea,
    hostname VARCHAR(260),
    first_seen TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX user_rec ON users(lic_id,lic_data,hostname);
CREATE UNIQUE INDEX user_hn_null ON users (lic_id,lic_data, (hostname IS NULL)) WHERE hostname is NULL;

CREATE TABLE files (
    id SERIAL PRIMARY KEY,
    chksum bytea UNIQUE /* file chksum */
);

CREATE TABLE dbs (
    id SERIAL PRIMARY KEY,
    file_path VARCHAR(260),
    idb_path VARCHAR(260),
    file_id INTEGER REFERENCES files(id),
    user_id INTEGER REFERENCES users(id)
);
CREATE UNIQUE INDEX db_paths ON dbs(file_id, user_id, idb_path);

CREATE TABLE funcs (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    len INTEGER NOT NULL,
    db_id INTEGER REFERENCES dbs(id) NOT NULL,
    chksum bytea, /* function chksum */
    metadata bytea,
    rank INTEGER,

    push_dt TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    update_dt TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX funcs_db ON funcs(chksum, db_id);
CREATE INDEX funcs_ranking ON funcs(chksum,rank);
CREATE INDEX func_chksum ON funcs(chksum);
