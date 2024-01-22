// @generated automatically by Diesel CLI.

diesel::table! {
    dbs (id) {
        id -> Int4,
        file_path -> Nullable<Varchar>,
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
        hostname -> Nullable<Varchar>,
        first_seen -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(dbs -> files (file_id));
diesel::joinable!(dbs -> users (user_id));
diesel::joinable!(funcs -> dbs (db_id));

diesel::allow_tables_to_appear_in_same_query!(dbs, files, funcs, users,);
