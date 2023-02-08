use std::borrow::Cow;
use time::OffsetDateTime;

use diesel::prelude::*;

#[derive(Queryable)]
#[diesel(table_name = funcs)]
#[diesel(table_name = func_ranks)]
pub struct Function<'a> {
    pub id: i32,
    pub name: Cow<'a, str>,
    pub len: i32,
    pub db_id: i32,
    pub chksum: Option<Cow<'a, [u8]>>,
    pub metadata: Option<Cow<'a, [u8]>>,
    pub rank: Option<i32>,
    pub push_dt: Option<OffsetDateTime>,
    pub update_dt: Option<OffsetDateTime>,
}
