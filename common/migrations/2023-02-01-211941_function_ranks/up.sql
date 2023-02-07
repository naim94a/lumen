CREATE VIEW func_ranks AS (
    SELECT distinct on (len,chksum) f.* FROM funcs f
    INNER JOIN (
        SELECT chksum, len, MAX(rank) max_rank FROM funcs
        GROUP BY (chksum, len)
    ) j
    ON j.chksum=f.chksum AND j.max_rank = f.rank AND j.len = f.len
);
