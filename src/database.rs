use rusqlite::types::FromSql;
use rusqlite::{ffi, Connection};

use tokio::sync::Mutex;

use crate::server::Error;
use crate::models;

type Result<T> = std::result::Result<T, Error>;

fn error_code_match(
    err : &rusqlite::Error,
    code : ffi::ErrorCode,
    ext : i64,
) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _)
            if e.code == code
            && i64::from(e.extended_code) == ext)
}


macro_rules! db_method {
    ($name:ident (
        &$self:ident,
        $conn:ident,
        $($pname:ident : $ptype:ty),*
    ) -> $ret:ty $body:block ) => {
        pub async fn $name (&$self, $( $pname : $ptype, )* ) -> $ret {
            let $conn = $self.conn.lock().await;
            tokio::task::block_in_place(|| $body)
        }
    }
}


pub struct Database {
    conn : Mutex<Connection>
}

impl Database {
    pub fn new(file : &str) -> Result<Self> {
        let conn = Connection::open(file)?;
        conn.pragma_update(None, "foreign_keys", &"ON")?;

        let conn = Mutex::new(conn);

        Ok(Self{ conn })
    }

    db_method!{ get_user_by_name(&self, conn, name : &str) -> Result<models::User> {
        let mut stmt = conn.prepare_cached("SELECT * FROM users WHERE users.name = ?")?;

        let mut rows = stmt.query(rusqlite::params![name])?;

        let row = rows.next()?.ok_or(Error::UserNotFound(name.to_string()))?;

        Ok(row_parse(row)?)
    }}

    db_method!{ increment_token(&self, conn, name : &str) -> Result<()> {
        conn.prepare_cached("
            UPDATE users
            SET token_version = token_version + 1
            WHERE name = ?
            ")?
            .execute(rusqlite::params![name])?;

        Ok(())
    }}

    db_method!{ insert_user(&self, conn, name : &str, pass_hash : &str) -> Result<()> {
        conn.prepare_cached("INSERT INTO users (name, pass_hash) VALUES (?, ?)")?
            .execute(rusqlite::params![name, pass_hash])
            .map(|_| ())
            .map_err(|err| {
                if error_code_match(
                    &err,
                    ffi::ErrorCode::ConstraintViolation,
                    2067
                ) {
                    Error::DuplicateName(name.to_string())
                } else {
                    err.into()
                }
            })
    }}
}

struct Row<'a> {
    off :   usize,
    inner : &'a rusqlite::Row<'a>,
    cols :  Vec<&'a str>,
}

impl<'a> From<&'a rusqlite::Row<'a>> for Row<'a> {
    fn from(r : &'a rusqlite::Row<'a>) -> Row<'a> {
        Row {
            off :   0,
            cols :  r.column_names(),
            inner : r,
        }
    }
}

fn row_parse<'a, T : FromRow>(row : &'a rusqlite::Row<'a>) -> Result<T> {
    T::from_row(&mut row.into())
}

impl<'a> Row<'a> {
    fn column_names(&self) -> &[&'a str] {
        &self.cols
    }

    fn get<T : FromSql>(&self, idx : usize) -> rusqlite::Result<T> {
        self.inner.get(idx + self.off)
    }

    fn advance(&mut self, n : usize) {
        self.off += n;
    }
}

trait FromRow: Sized {
    fn column_count() -> usize;
    fn from_row(row : &mut Row) -> Result<Self>;
}

impl<T, U> FromRow for (T, U)
where
    T : FromRow,
    U : FromRow,
{
    fn column_count() -> usize {
        T::column_count() + U::column_count()
    }

    fn from_row(row : &mut Row) -> Result<Self> {
        let t = T::from_row(row)?;
        row.advance(T::column_count());
        let u = U::from_row(row)?;

        Ok((t, u))
    }
}

macro_rules! impl_from_row {
    ($table:ident, $ty:ty { $($field:ident),* }) => {

        impl FromRow for $ty {
            fn column_count() -> usize {
                const N : usize = [
                    $(
                        stringify!($field),
                    )*
                ].len();

                N
            }

            fn from_row(row : &mut Row) -> Result<$ty> {
                fn find(slc : &[&str], s : &str) -> Option<usize> {
                    for (i, v) in slc.iter().enumerate() {
                        if v == &s {
                            return Some(i)
                        }
                    }

                    None
                }

                let cols = row.column_names();

                let m = &[
                    $(
                        find(&cols, stringify!($field)),
                    )*
                ];

                let mut it = m.iter().copied();


                Ok(Self{
                $(
                    $field : row.get(it.next().unwrap().unwrap())?,
                )*
                })
            }
        }
    }
}

impl_from_row! {users, models::User {
    name, pass_hash, token_version
}}

