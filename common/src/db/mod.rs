use log::*;
use tokio_postgres::{Client, NoTls};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use crate::config::Config;

pub type DynConfig = dyn crate::config::HasConfig + Send + Sync;

pub struct Database {
    config: Arc<DynConfig>,
    conn: RwLock<Client>,
    cache: RwLock<HashMap<String, tokio_postgres::Statement>>,
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
    pub async fn open(config: Arc<DynConfig>) -> Result<Self, tokio_postgres::Error> {
        let client = Self::connect(config.get_config()).await?;

        Ok(Database{
            config,
            conn: RwLock::new(client),
            cache: RwLock::new(HashMap::new()),
        })
    }

    async fn connect_tls(conn_info: &Config) -> Result<tokio_postgres::Client, tokio_postgres::Error> {
        use postgres_native_tls::MakeTlsConnector;
        use native_tls::{TlsConnector, Certificate, Identity};

        let mut tls_connector = TlsConnector::builder();

        if let Some(ref client_identity) = conn_info.database.client_id {
            let client_identity = tokio::fs::read(client_identity).await.expect("failed to read db's client id");
            let client_identity = Identity::from_pkcs12(&client_identity, "").expect("failed to load db's client identity (PKCS12)");
            tls_connector.identity(client_identity);
        }

        if let Some(ref server_ca) = conn_info.database.server_ca {
            let server_ca = tokio::fs::read(server_ca).await.expect("failed to read db's server ca");
            let server_ca = Certificate::from_pem(&server_ca).expect("failed to load db's server ca (PEM)");
            tls_connector.add_root_certificate(server_ca);
        }

        let tls_connector = tls_connector
            .danger_accept_invalid_hostnames(true)
            .build()
            .expect("failed to build TlsConnector");

        let connector = MakeTlsConnector::new(tls_connector);

        let (client, conn) = tokio_postgres::connect(&conn_info.database.connection_info, connector).await?;
        info!("database connected (tls).");
        
        tokio::spawn(async {
            if let Err(e) = conn.await {
                error!("db connection error: {}", e);
            }
        });

        Ok(client)
    }

    async fn connect_plain(conn_info: &str) -> Result<tokio_postgres::Client, tokio_postgres::Error> {
        let (client, conn) = tokio_postgres::connect(conn_info, NoTls).await?;
        info!("database connected.");

        tokio::spawn(async {
            if let Err(e) = conn.await {
                error!("db connection error: {}", e);
            }
        });

        Ok(client)
    }

    async fn connect(conn_info: &Config) -> Result<tokio_postgres::Client, tokio_postgres::Error> {
        if conn_info.database.use_tls {
            info!("connecting with TLS...");
            Self::connect_tls(conn_info).await
        }
        else {
            info!("connecting plain...");
            Self::connect_plain(&conn_info.database.connection_info).await
        }
    }

    async fn prepare_cached<'a, 'b>(&'a self, sql: &'b str) -> Result<tokio_postgres::Statement, tokio_postgres::Error> {
        {
            let rd = self.cache.read().await;
            if let Some(v) = rd.get(sql) {
                return Ok(v.clone());
            }
        }
        {
            let stmt = self.conn.read().await.prepare(sql).await?;
            let mut wr = self.cache.write().await;
            wr.insert(sql.to_string(), stmt);

            let v = wr.get(sql).expect("failed to get recently added value");
            Ok(v.clone())
        }
    }

    pub async fn get_funcs<'a>(&self, funcs: &[crate::rpc::PullMetadataFunc<'a>]) -> Result<Vec<Option<FunctionInfo>>, tokio_postgres::Error> {
        let stmt = self.prepare_cached(r#"
        WITH best AS (
            select chksum,MAX(rank) as maxrank from funcs f1
            WHERE chksum = ANY($1)
            GROUP BY chksum 
        )
        SELECT f2.name,f2.len,f2.metadata,f2.chksum FROM best
        LEFT JOIN funcs f2 ON (best.chksum=f2.chksum AND best.maxrank=f2.rank)
        "#).await?;

        let conn = self.conn.read().await;

        let chksums: Vec<&[u8]> = funcs.iter().map(|v| v.mb_hash.as_ref()).collect();

        let rows = conn.query(&stmt, &[&chksums]).await?;
        let mut partial: HashMap<Vec<u8>, FunctionInfo> = rows
            .into_iter()
            .map(|row| {
                let chksum: Vec<u8> = row.get(3);
                let v = FunctionInfo {
                    name: row.get(0),
                    len: row.get::<_, i32>(1) as u32,
                    data: row.get(2),
                    popularity: 0,
                };

                (chksum, v)
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

    pub async fn get_or_create_user<'a>(&self, user: &'a crate::rpc::RpcHello<'a>, funcs: Option<&'a crate::rpc::PushMetadata<'a>>) -> Result<i32, tokio_postgres::Error> {
        let stmt = self.prepare_cached(
            r#"
            WITH ins AS (
                INSERT INTO users(lic_id, lic_data, hostname)
                VALUES ($1, $3, $2)
                ON CONFLICT DO NOTHING
                RETURNING id
            )
            SELECT id FROM ins
            UNION
            SELECT id FROM users WHERE lic_id=$1 AND lic_data=$3 AND (($2 is not null AND hostname = $2) OR ($2 is null AND hostname is null))
            "#).await?;
            
        let lic_id = &user.lic_number[..];
        let lic_data = user.license_data;
        let hostname = funcs.map(|v| v.hostname);

        let row = self.conn.read().await.query(&stmt, &[&lic_id, &hostname, &lic_data]).await?;
        if row.len() > 0 {
            let id = row[0].get(0);
            if row.len() > 1 {
                let vals: Vec<i32> = row.iter().map(|v| v.get(0)).collect();
                debug!("expected single row, got: {:?}", &vals);
            }
            Ok(id)
        } else {
            error!("no rows for user. ret 0");
            Ok(0)
        }
    }

    async fn get_or_create_file<'a>(&self, funcs: &'a crate::rpc::PushMetadata<'a>) -> Result<i32, tokio_postgres::Error> {
        let stmt = self.prepare_cached(r#"
        WITH ins AS (
            INSERT INTO files(chksum)
            VALUES ($1)
            ON CONFLICT(chksum) DO NOTHING
            RETURNING id
        )
        SELECT id FROM files WHERE chksum=$1
        UNION
        SELECT id FROM ins
        "#).await?;

        let hash = &funcs.md5[..];

        let id: i32 = self.conn.read().await
            .query_one(&stmt, &[&hash]).await?
            .get(0);
        Ok(id)
    }

    async fn get_or_create_db<'a>(&self, user: &'a crate::rpc::RpcHello<'a>, funcs: &'a crate::rpc::PushMetadata<'a>) -> Result<i32, tokio_postgres::Error> {
        let file_id = self.get_or_create_file(funcs);
        let user_id = self.get_or_create_user(user, Some(funcs));

        let (file_id, user_id): (i32, i32) = futures_util::try_join!(file_id, user_id)?;

        let stmt = self.prepare_cached(r#"
        WITH ins AS (
            INSERT INTO dbs (user_id, file_id, file_path, idb_path)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT(idb_path,file_id,user_id) DO NOTHING
            RETURNING id
        )
        SELECT id FROM dbs WHERE user_id=$1 AND file_id=$2 AND idb_path=$4
        UNION
        SELECT id FROM ins
        "#).await?;

        let idb_path = funcs.idb_path;
        let file_path = funcs.file_path;

        trace!("fid={}; uid={}", file_id, user_id);
        let row = self.conn.read().await
            .query_one(&stmt, &[&user_id, &file_id, &file_path, &idb_path]).await?;

        let db_id = row.get(0);

        Ok(db_id)
    }

    pub async fn push_funcs<'a, 'b>(&'b self, user: &'a crate::rpc::RpcHello<'a>, funcs: &'a crate::rpc::PushMetadata<'a>, scores: &[u32]) -> Result<Vec<bool>, tokio_postgres::Error> {
        let db_id = self.get_or_create_db(user, funcs).await?;
        
        let stmt = self.prepare_cached(r#"
        INSERT INTO funcs AS f (name, len, chksum, metadata, db_id, rank)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (db_id,chksum) DO UPDATE 
            SET metadata=$4, rank=$6, name=$1, update_dt=CURRENT_TIMESTAMP
            WHERE f.db_id=$5 AND f.chksum=$3 AND f.len=$2
        RETURNING exists(SELECT 1 FROM funcs WHERE chksum=$3)
        "#).await?;

        debug_assert_eq!(scores.len(), funcs.funcs.len());

        let mut res = Vec::with_capacity(funcs.funcs.len());

        // NOTE: Do not access self.conn/prepare_cached before dropping tx - it will deadlock!
        {
            let mut tx = self.conn.write().await;
            let tx = tx.transaction().await?;

            for (func, &score) in funcs.funcs.iter().zip(scores.iter()) {
                let name = func.name;
                let len = func.func_len as i32;
                let chksum = func.hash;
                let md = func.func_data;
                let score = score as i32;
                let row_exists = tx.query_one(&stmt, &[
                    &name, &len, &chksum, &md, &db_id, &score
                ]).await?;

                let row_exists: bool = row_exists.try_get(0)?;

                res.push(!row_exists);
            }

            tx.commit().await?;
        }

        Ok(res)
    }

    pub async fn is_online(&self) -> bool {
        let read = self.conn.read().await;
        !read.is_closed()
    }

    pub async fn reconnect(&self) -> Result<(), tokio_postgres::Error> {
        let connection = Self::connect(self.config.get_config()).await?;
        
        let conn = &mut *self.conn.write().await;

        self.cache.write().await.clear();

        *conn = connection;
        Ok(())
    }

    pub async fn get_stats(&self) -> Result<DbStats, tokio_postgres::Error> {
        let stmt = self.prepare_cached(r#"
        SELECT 
            (SELECT COUNT(*)::int FROM users) as users,
            (SELECT COUNT(distinct lic_id)::int FROM users) as hosts,
            (SELECT COUNT(distinct chksum)::int FROM funcs) as funcs,
            (SELECT COUNT(*)::int FROM funcs) as total_funcs,
            (SELECT COUNT(*)::int FROM dbs) as dbs,
            (SELECT COUNT(*)::int FROM files) as files
        "#).await?;
        let db = self.conn.read().await;
        let row = db.query_one(&stmt, &[]).await?;

        Ok(DbStats {
            unique_lics: row.try_get(0)?,
            unique_hosts_per_lic: row.try_get(1)?,
            unique_funcs: row.try_get(2)?,
            total_funcs: row.try_get(3)?,
            dbs: row.try_get(4)?,
            unique_files: row.try_get(5)?,
        })
    }

    pub async fn get_file_funcs(&self, md5: &[u8], offset: i64, limit: i64) -> Result<Vec<(String, u32, [u8; 16])>, tokio_postgres::Error> {
        let stmt = self.prepare_cached(r#"
        SELECT fns.name, fns.len, fns.chksum FROM funcs AS fns
        LEFT JOIN dbs AS d ON (d.id=fns.db_id)
        LEFT JOIN files AS f ON (d.file_id=f.id)
        WHERE 
            f.chksum=$1
        LIMIT $2
        OFFSET $3
        "#).await?;
        let db = self.conn.read().await;
        let rows = db.query(&stmt, &[&md5, &limit, &offset]).await?;

        let res = rows.into_iter()
            .map(|row| {
                let name: String = row.get(0);
                let len: i32 = row.get(1);
                let md5_a: Vec<u8> = row.get(2);

                let mut md5 = [0u8; 16];
                md5.copy_from_slice(&md5_a);

                (name, len as u32, md5)
            })
            .collect();
        Ok(res)
    }

    pub async fn get_files_with_func(&self, func: &[u8]) -> Result<Vec<[u8; 16]>, tokio_postgres::Error> {
        let stmt = self.prepare_cached(r#"
        SELECT DISTINCT f.chksum FROM files f
        LEFT JOIN dbs d ON (d.file_id = f.id)
        LEFT JOIN funcs fns ON (fns.db_id = d.id)
        WHERE
            fns.chksum = $1
        "#).await?;
        let db = self.conn.read().await;
        let rows = db.query(&stmt, &[&func]).await?;

        let res = rows
            .into_iter()
            .map(|v| {
                let mut chksum = [0u8; 16];
                let v: Vec<u8> = v.get(0);
                chksum.copy_from_slice(&v);
                chksum
            })
            .collect();
        Ok(res)
    }
}
