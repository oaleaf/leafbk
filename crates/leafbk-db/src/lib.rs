pub extern crate redis;

use redis::{FromRedisValue, RedisResult, Value};

pub struct RedisClient {
    pub client: redis::Client,
}

pub struct OptionalString(Option<String>);

impl FromRedisValue for OptionalString {
    fn from_redis_value(v: &Value) -> RedisResult<Self> {
        if let Value::Nil = v {
            return Ok(Self(None));
        }

        String::from_redis_value(v).map(|it| Self(Some(it)))
    }
}

impl OptionalString {
    pub fn into_inner(self) -> Option<String> {
        self.0
    }
}

#[macro_export]
macro_rules! redis_key {
    ($v:literal) => {
        concat!("leafbk:", $v)
    };
    ($v:expr) => {
        format!("leafbk:{}", $v)
    };
}

#[macro_export]
macro_rules! get {
    ($conn:expr, $k:literal, $r:ty) => {
        <$crate::redis::aio::Connection as $crate::redis::AsyncCommands>::get::<_, $r>($conn, $crate::redis_key!($k))
    };
    ($conn:expr, $k:expr, $r:ty) => {
        <$crate::redis::aio::Connection as $crate::redis::AsyncCommands>::get::<_, $r>($conn, $crate::redis_key!($k))
    };

    ($conn:expr, $k:literal, $r:ty, @await) => {
        $crate::get!($conn, $k, $r).await
    };
    ($conn:expr, $k:expr, $r:ty, @await) => {
        $crate::get!($conn, $k, $r).await
    };

    ($conn:expr, $k:literal, $r:ty, @unwrap) => {
        $crate::get!($conn, $k, $r, @await).unwrap()
    };
    ($conn:expr, $k:expr, $r:ty, @unwrap) => {
        $crate::get!($conn, $k, $r, @await).unwrap()
    };
}

#[macro_export]
macro_rules! set {
    ($conn:expr, $k:literal, $v:expr, $r:ty) => {
        <$crate::redis::aio::Connection as $crate::redis::AsyncCommands>::set::<_, _, $r>($conn, $crate::redis_key!($k), $v)
    };
    ($conn:expr, $k:expr, $v:expr, $r:ty) => {
        <$crate::redis::aio::Connection as $crate::redis::AsyncCommands>::set::<_, _, $r>($conn, $crate::redis_key!($k), $v)
    };

    ($conn:expr, $k:literal, $v:expr, $r:ty, @await) => {
        $crate::set!($conn, $k, $v, $r).await
    };
    ($conn:expr, $k:expr, $v:expr, $r:ty, @await) => {
        $crate::set!($conn, $k, $v, $r).await
    };

    ($conn:expr, $k:literal, $v:expr, $r:ty, @unwrap) => {
        $crate::set!($conn, $k, $v, $r, @await).unwrap()
    };
    ($conn:expr, $k:expr, $v:expr, $r:ty, @unwrap) => {
        $crate::set!($conn, $k, $v, $r, @await).unwrap()
    };
}
