-- don't allow table to be modified until we're done...
LOCK TABLE users;

-- delete funcs that belong to users
DELETE FROM funcs USING dbs, users
WHERE dbs.id=funcs.db_id
    AND users.id=dbs.user_id
    AND users.cred_id IS NOT NULL;

-- delete dbs that belong to users
DELETE FROM dbs USING users WHERE dbs.user_id=users.id AND users.cred_id IS NOT NULL;

-- delete all users with creds...
DELETE FROM users WHERE cred_id is NOT NULL;
DROP TABLE creds CASCADE;

CREATE UNIQUE INDEX IF NOT EXISTS user_rec ON users(lic_id,lic_data,hostname);
CREATE UNIQUE INDEX IF NOT EXISTS user_hn_null ON users (lic_id,lic_data, (hostname IS NULL)) WHERE hostname is NULL;
DROP INDEX user_cred_idx;

ALTER TABLE users DROP COLUMN cred_id;
