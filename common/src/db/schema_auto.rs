// @generated automatically by Diesel CLI.

diesel::table! {
    creds (id) {
        id -> Int4,
        #[max_length = 256]
        username -> Varchar,
        #[max_length = 256]
        email -> Varchar,
        passwd_salt -> Nullable<Bytea>,
        passwd_iters -> Int4,
        passwd_hash -> Nullable<Bytea>,
        last_active -> Nullable<Timestamptz>,
        creation_dt -> Timestamptz,
        is_admin -> Bool,
        is_enabled -> Bool,
    }
}

diesel::table! {
    dbs (id) {
        id -> Int4,
        #[max_length = 260]
        file_path -> Nullable<Varchar>,
        #[max_length = 260]
        idb_path -> Nullable<Varchar>,
        file_id -> Nullable<Int4>,
        user_id -> Nullable<Int4>,
    }
}

diesel::table! {
    files (id) {
        id -> Int4,
        chksum -> Nullable<Bytea>,
    }
}

diesel::table! {
    funcs (id) {
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

diesel::table! {
    users (id) {
        id -> Int4,
        lic_id -> Nullable<Bytea>,
        lic_data -> Nullable<Bytea>,
        #[max_length = 260]
        hostname -> Nullable<Varchar>,
        first_seen -> Nullable<Timestamptz>,
        cred_id -> Nullable<Int4>,
    }
}

diesel::joinable!(dbs -> files (file_id));
diesel::joinable!(dbs -> users (user_id));
diesel::joinable!(funcs -> dbs (db_id));
diesel::joinable!(users -> creds (cred_id));

diesel::allow_tables_to_appear_in_same_query!(
    creds,
    dbs,
    files,
    funcs,
    users,
);
