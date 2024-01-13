use log::*;
use postgres_native_tls::MakeTlsConnector;
use serde::Serialize;
use time::OffsetDateTime;
use tokio_postgres::{tls::MakeTlsConnect, Socket, NoTls};
use std::collections::HashMap;
use crate::async_drop::{AsyncDropper, AsyncDropGuard};
mod schema_auto;
pub mod schema;

use diesel::{upsert::excluded, ExpressionMethods, QueryDsl, NullableExpressionMethods, sql_types::{Array, Binary, VarChar, Integer}, query_builder::{QueryFragment, Query}};
use diesel_async::{RunQueryDsl, pooled_connection::ManagerConfig};

pub type DynConfig = dyn crate::config::HasConfig + Send + Sync;

pub struct Database {
    tls_connector: Option<MakeTlsConnector>,
    diesel: diesel_async::pooled_connection::bb8::Pool<diesel_async::AsyncPgConnection>,
    dropper: AsyncDropper,
}

pub struct FunctionInfo {
    pub name: String,
    pub len: u32,
    pub data: Vec<u8>,
    pub popularity: u32,
}

#[derive(Debug, Serialize)]
pub struct DbStats {
    unique_lics: i32,
    unique_hosts_per_lic: i32,

    unique_funcs: i32,
    total_funcs: i32,

    dbs: i32,
    unique_files: i32,
}

impl Database {
    pub async fn open(config: &crate::config::Database) -> Result<Self, anyhow::Error> {
        let connection_string = config.connection_info.as_str();
        let tls_connector = if config.use_tls {
            Some(Self::make_tls(config).await)
        } else {
            None
        };

        let (dropper, worker) = AsyncDropper::new();
        tokio::task::spawn(worker);

        let diesel = Self::make_bb8_pool(connection_string, tls_connector.clone()).await?;

        Ok(Database {
            tls_connector,
            dropper,
            diesel,
        })
    }

    async fn make_pg_client<T>(db_url: &str, tls: T) -> diesel::result::ConnectionResult<diesel_async::AsyncPgConnection>
        where T: MakeTlsConnect<Socket>,
        T::Stream: Send + 'static {
        let (cli, conn) = tokio_postgres::connect(db_url, tls)
            .await
            .map_err(|e| {
                error!("failed to connect db: {e}");
                diesel::result::ConnectionError::BadConnection(format!("{e}"))
            })?;

        tokio::spawn(async move {
            if let Err(e) = conn.await {
                error!("connection task error: {e}");
            }
        });

        diesel_async::AsyncPgConnection::try_from(cli).await
    }

    async fn make_bb8_pool(db_url: &str, tls: Option<MakeTlsConnector>) -> Result<diesel_async::pooled_connection::bb8::Pool<diesel_async::AsyncPgConnection>, anyhow::Error> {
        let mut config = ManagerConfig::default();
        config.custom_setup = Box::new(move |db_url| {
            let tls = tls.clone();
            Box::pin(async move {
                if let Some(tls) = tls {
                    Self::make_pg_client(db_url, tls).await
                } else {
                    Self::make_pg_client(db_url, NoTls).await
                }
            })
        });
        let cfg = diesel_async::pooled_connection::AsyncDieselConnectionManager::<diesel_async::AsyncPgConnection>::new_with_config(db_url, config);

        let pool = diesel_async::pooled_connection::bb8::Pool::builder()
            .min_idle(Some(1))
            .build(cfg)
            .await?;
        Ok(pool)
    }

    async fn make_tls(database: &crate::config::Database) -> MakeTlsConnector {
        use native_tls::{TlsConnector, Certificate, Identity};

        let mut tls_connector = TlsConnector::builder();

        if let Some(ref client_identity) = database.client_id {
            let client_identity = tokio::fs::read(client_identity).await.expect("failed to read db's client id");
            let client_identity = Identity::from_pkcs12(&client_identity, "").expect("failed to load db's client identity (PKCS12)");
            tls_connector.identity(client_identity);
        }

        if let Some(ref server_ca) = database.server_ca {
            let server_ca = tokio::fs::read(server_ca).await.expect("failed to read db's server ca");
            let server_ca = Certificate::from_pem(&server_ca).expect("failed to load db's server ca (PEM)");
            tls_connector.add_root_certificate(server_ca);
        }

        let tls_connector = tls_connector
            .danger_accept_invalid_hostnames(true)
            .build()
            .expect("failed to build TlsConnector");

        MakeTlsConnector::new(tls_connector)
    }

    pub async fn get_funcs(&self, funcs: &[crate::rpc::PullMetadataFunc<'_>]) -> Result<Vec<Option<FunctionInfo>>, anyhow::Error> {
        let chksums: Vec<&[u8]> = funcs.iter().map(|v| v.mb_hash).collect();

        let rows: Vec<(String, i32, Vec<u8>, Vec<u8>)> = {
            let conn = &mut self.diesel.get().await?;

            let ct = self.cancel_guard(&*conn);

            let res: Vec<_> = BestMds(chksums.as_slice())
                .get_results::<_>(conn).await?;
            ct.consume();
            res
        };

        let mut partial: HashMap<Vec<u8>, FunctionInfo> = rows
            .into_iter()
            .map(|row| {
                let v = FunctionInfo {
                    name: row.0,
                    len: row.1 as u32,
                    data: row.2,
                    popularity: 0,
                };

                (row.3, v)
            })
            .collect();

        let results = partial.len();

        let res: Vec<Option<FunctionInfo>> = chksums.iter().map(|&chksum| {
            partial.remove(chksum)
        }).collect();

        trace!("found {}/{} results", results, chksums.len());
        debug_assert_eq!(chksums.len(), res.len());
        Ok(res)
    }

    pub async fn get_or_create_user<'a>(&self, user: &'a crate::rpc::RpcHello<'a>, hostname: &str) -> Result<i32, anyhow::Error> {
        use schema::users;

        let conn = &mut self.diesel.get().await?;

        let lic_id = &user.lic_number[..];
        let lic_data = user.license_data;

        let get_user = || users::table.select(users::id)
            .filter(users::lic_data.eq(lic_data))
            .filter(users::lic_id.eq(lic_id))
            .filter(users::hostname.eq(hostname));

        match get_user().get_result::<i32>(conn).await {
            Ok(v) => return Ok(v),
            Err(err) if err != diesel::result::Error::NotFound => return Err(err.into()),
            _ => {},
        };

        match diesel::insert_into(users::table)
            .values(vec![
                (
                    users::lic_id.eq(lic_id),
                    users::lic_data.eq(lic_data),
                    users::hostname.eq(hostname),
                )
            ])
            .returning(users::id) // xmax = 0 if the row is new
            .get_result::<i32>(conn)
            .await {
            Ok(v) => return Ok(v),
            Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)) => {},
            Err(e) => return Err(e.into()),
        }

        Ok(get_user().get_result::<i32>(conn).await?)
    }

    async fn get_or_create_file<'a>(&self, funcs: &'a crate::rpc::PushMetadata<'a>) -> Result<i32, anyhow::Error> {
        use schema::files::{table as files, chksum, id};

        let hash = &funcs.md5[..];

        let conn = &mut self.diesel.get().await?;

        let get_file = || files.filter(chksum.eq(hash)).select(id);

        match get_file().get_result::<i32>(conn).await {
            Ok(v) => return Ok(v),
            Err(err) if err != diesel::result::Error::NotFound => return Err(err.into()),
            _ => {},
        }

        match diesel::insert_into(files)
            .values(vec![(chksum.eq(hash),)])
            .returning(id)
            .get_result::<i32>(conn)
            .await {
            Ok(v) => return Ok(v),
            Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)) => {},
            Err(e) => return Err(e.into()),
        }
        Ok(get_file().get_result::<i32>(conn).await?)
    }

    async fn get_or_create_db<'a>(&self, user: &'a crate::rpc::RpcHello<'a>, funcs: &'a crate::rpc::PushMetadata<'a>) -> Result<i32, anyhow::Error> {
        use schema::dbs::{table as dbs, id as db_id, user_id as db_user, file_id as db_file_id, file_path, idb_path};

        let file_id = self.get_or_create_file(funcs);
        let user_id = self.get_or_create_user(user, funcs.hostname);

        let (file_id, user_id): (i32, i32) = futures_util::try_join!(file_id, user_id)?;

        let conn = &mut self.diesel.get().await?;

        let get_db = || {
            dbs.select(db_id)
                .filter(db_user.eq(user_id))
                .filter(db_file_id.eq(file_id))
                .filter(file_path.eq(funcs.file_path))
                .filter(idb_path.eq(funcs.idb_path))
        };

        match get_db().get_result::<i32>(conn).await {
            Ok(v) => return Ok(v),
            Err(err) if err != diesel::result::Error::NotFound => return Err(err.into()),
            _ => {},
        };

        match diesel::insert_into(dbs)
            .values(vec![(
                db_user.eq(user_id),
                db_file_id.eq(file_id),
                file_path.eq(funcs.file_path),
                idb_path.eq(funcs.idb_path),
            )])
            .returning(db_id)
            .get_result::<i32>(conn)
            .await {
            Ok(id) => return Ok(id),
            Err(diesel::result::Error::DatabaseError(diesel::result::DatabaseErrorKind::UniqueViolation, _)) => {},
            Err(e) => return Err(e.into()),
        };
        Ok(get_db().get_result::<i32>(conn).await?)
    }

    pub async fn push_funcs<'a, 'b>(&'b self, user: &'a crate::rpc::RpcHello<'a>, funcs: &'a crate::rpc::PushMetadata<'a>, scores: &[u32]) -> Result<Vec<bool>, anyhow::Error> {
        use futures_util::TryStreamExt;

        // postgres has a limitation of binding per statement (i16::MAX). Split large push requests into smaller chunks.
        const PUSH_FUNC_CHUNK_SIZE: usize = 3000;

        let db_id = self.get_or_create_db(user, funcs).await?;

        let mut rows = Vec::with_capacity(funcs.funcs.len().min(PUSH_FUNC_CHUNK_SIZE));
        let mut is_new = Vec::with_capacity(funcs.funcs.len());
        let conn = &mut self.diesel.get().await?;
        let f2 = diesel::alias!(schema::funcs as f2);

        for (idx, (func, &score)) in funcs.funcs.iter().zip(scores.iter()).enumerate() {
            let name = func.name;
            let len = func.func_len as i32;
            let chksum = func.hash;
            let md = func.func_data;
            let score = score as i32;

            rows.push((
                schema::funcs::name.eq(name),
                schema::funcs::len.eq(len),
                schema::funcs::chksum.eq(chksum),
                schema::funcs::metadata.eq(md),
                schema::funcs::rank.eq(score),
                schema::funcs::db_id.eq(db_id),
            ));

            if rows.len() < PUSH_FUNC_CHUNK_SIZE && idx < funcs.funcs.len() - 1 {
                continue;
            }

            let mut current_rows = Vec::with_capacity((funcs.funcs.len() - (idx + 1)).max(PUSH_FUNC_CHUNK_SIZE));
            std::mem::swap(&mut current_rows, &mut rows);

            diesel::insert_into(schema::funcs::table)
                .values(current_rows)
                .on_conflict((schema::funcs::chksum, schema::funcs::db_id))
                .do_update()
                    .set((
                        schema::funcs::name.eq(excluded(schema::funcs::name)),
                        schema::funcs::metadata.eq(excluded(schema::funcs::metadata)),
                        schema::funcs::rank.eq(excluded(schema::funcs::rank)),
                        schema::funcs::update_dt.eq(diesel::dsl::now)
                    ))
                .returning(diesel::dsl::not(diesel::dsl::exists(f2.filter(f2.field(schema::funcs::chksum).eq(schema::funcs::chksum))))) // xmax=0 when a new row is created.
                .load_stream::<bool>(conn)
                .await?
                .try_fold(&mut is_new, |acc, item: bool| {
                    acc.push(item);
                    futures_util::future::ready(Ok(acc))
                })
                .await?;
        }

        Ok(is_new)
    }

    pub async fn get_file_funcs(&self, md5: &[u8], offset: i64, limit: i64) -> Result<Vec<(String, i32, Vec<u8>)>, anyhow::Error> {
        let conn = &mut self.diesel.get().await?;
        let results = schema::funcs::table
            .left_join(schema::dbs::table.left_join(schema::files::table))
            .select((schema::funcs::name.assume_not_null(), schema::funcs::len.assume_not_null(), schema::funcs::chksum.assume_not_null()))
            .filter(schema::files::chksum.eq(md5))
            .offset(offset)
            .limit(limit)
            .get_results::<(String, i32, Vec<u8>)>(conn).await?;
        Ok(results)
    }

    pub async fn get_files_with_func(&self, func: &[u8]) -> Result<Vec<Vec<u8>>, anyhow::Error> {
        let conn = &mut self.diesel.get().await?;

        let res = schema::files::table
            .left_join(schema::dbs::table.left_join(schema::funcs::table))
            .select(schema::files::chksum.assume_not_null())
            .distinct()
            .filter(schema::funcs::chksum.eq(func))
            .get_results::<Vec<u8>>(conn)
            .await?;
        Ok(res)
    }

    fn cancel_guard(&self, conn: &diesel_async::pooled_connection::bb8::PooledConnection<'_, diesel_async::AsyncPgConnection>) -> AsyncDropGuard {
        let token = conn.cancel_token();
        let tls_connector = self.tls_connector.clone();
        self.dropper.defer(async move {
            debug!("cancelling query...");

            if let Some(tls) = tls_connector {
                let _ = token.cancel_query(tls).await;
            } else {
                let _ = token.cancel_query(NoTls).await;
            }
        })
    }

    pub async fn delete_metadata(&self, req: &crate::rpc::DelHistory<'_>) -> Result<(), anyhow::Error> {
        use schema::funcs::{table as funcs, chksum};

        let chksums = req.funcs.iter()
            .map(|v| v.as_slice())
            .collect::<Vec<_>>();

        let conn = &mut self.diesel.get().await?;
        let rows_modified = diesel::delete(funcs.filter(chksum.eq_any(&chksums)))
            .execute(conn)
            .await?;

        debug!("deleted {rows_modified} rows");

        Ok(())
    }

    pub async fn get_func_histories(&self, chksum: &[u8], limit: u32) -> Result<Vec<(OffsetDateTime, String, Vec<u8>)>, anyhow::Error> {
        let conn = &mut self.diesel.get().await?;
        let rows = &schema::funcs::table
            .select((
                schema::funcs::update_dt.assume_not_null(),
                schema::funcs::name,
                schema::funcs::metadata.assume_not_null()
            ));
        let rows = rows.limit(limit as i64)
            .order_by(schema::funcs::update_dt.desc())
            .filter(
                schema::funcs::chksum.eq(chksum)
            )
            .get_results::<(time::OffsetDateTime, String, Vec<u8>)>(conn)
            .await?;
        Ok(rows)
    }
}

// This is eww, but it's the fastest.
struct BestMds<'a>(&'a [&'a [u8]]);
impl<'a> QueryFragment<diesel::pg::Pg> for BestMds<'a> {
    fn walk_ast<'b>(&'b self, mut pass: diesel::query_builder::AstPass<'_, 'b, diesel::pg::Pg>) -> diesel::QueryResult<()> {
        pass.push_sql(r#"WITH best AS (
            select chksum,MAX(rank) as maxrank from funcs f1
            WHERE chksum = ANY("#);
        pass.push_bind_param::<Array<Binary>, _>(&self.0)?;
        pass.push_sql(r#")
            GROUP BY chksum
        )
        SELECT f2.name,f2.len,f2.metadata,f2.chksum FROM best
        LEFT JOIN funcs f2 ON (best.chksum=f2.chksum AND best.maxrank=f2.rank)"#);
        Ok(())
    }
}
impl<'a> diesel::query_builder::QueryId for BestMds<'a> {
    type QueryId = BestMds<'static>;
}
impl<'a> Query for BestMds<'a> {
    type SqlType = (VarChar, Integer, Binary, Binary);
}
