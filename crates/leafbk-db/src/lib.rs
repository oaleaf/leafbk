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
