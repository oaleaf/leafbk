#[macro_use]
extern crate rocket;
extern crate argon2;

use crate::tokio::io::AsyncReadExt;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, Validation};
use redis::{AsyncCommands, FromRedisValue, RedisError, RedisResult, Value};
use rocket::data::{Limits, ToByteUnit};
use rocket::form::Form;
use rocket::fs::{NamedFile, TempFile};
use rocket::http::{ContentType, Status};
use rocket::outcome::IntoOutcome;
use rocket::request::FromRequest;
use rocket::response::Responder;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::{request, tokio, Build, Config, Request, Rocket, State};
use std::borrow::Cow;
use std::io;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::str::FromStr;

const ARGON_CFG: argon2::Config = {
    use argon2::*;

    Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: 65536,
        time_cost: 10,
        lanes: 4,
        thread_mode: ThreadMode::Sequential,
        secret: &[],
        ad: &[],
        hash_length: 32,
    }
};

macro_rules! k {
    ($v:literal) => {
        concat!("leafbk-media:", $v)
    };
    ($v:expr) => {
        format!("leafbk-media:{}", $v)
    };
}

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[derive(Debug, Deserialize)]
#[serde(crate = "::rocket::serde")]
struct CreateUserInfo {
    username: String,
    pass: String,
}

#[derive(Debug, Serialize)]
#[serde(crate = "::rocket::serde")]
struct CreateUserResponse {
    token: String,
}

#[post("/users", format = "application/json", data = "<user>")]
async fn create_user(
    user: Json<CreateUserInfo>,
    pk: &State<JWTPK>,
    redis: &State<RedisClient>,
) -> Result<Json<CreateUserResponse>, Status> {
    if !validate_username(&user.username) {
        return Err(Status::UnprocessableEntity);
    }

    if !validate_password(&user.pass) {
        return Err(Status::UnprocessableEntity);
    }

    let mut conn = redis.client.get_tokio_connection().await.unwrap();

    let v: OptionalString = conn.get(k!("user:username")).await.unwrap();
    let v = v.into_inner();

    if let Some(v) = v {
        warn!("User already registered: {}", v);
        return Err(Status::Conflict);
    }

    let _: () = conn
        .set(k!("user:username"), user.0.username.clone())
        .await
        .unwrap();

    const SALT: &[u8] = match option_env!("SALT") {
        Some(s) => s.as_bytes(),
        None => b"aaaaaaaaaaaa",
    };

    let hashed_pass = rocket::tokio::task::block_in_place(|| {
        argon2::hash_encoded(user.0.pass.as_bytes(), SALT, &ARGON_CFG)
    })
    .unwrap();

    let _: () = conn.set(k!("user:pass"), hashed_pass).await.unwrap();

    let key = ApiKey::create(user.username.clone(), &pk);

    Ok(Json(CreateUserResponse {
        token: key.auth_token.into_owned(),
    }))
}

#[derive(Debug, Deserialize)]
#[serde(crate = "::rocket::serde")]
struct LoginUserInfo {
    username: String,
    pass: String,
}

#[derive(Debug, Serialize)]
#[serde(crate = "::rocket::serde")]
struct LoginResponse {
    token: String,
}

pub struct RedisClient {
    client: redis::Client,
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
    fn into_inner(self) -> Option<String> {
        self.0
    }
}

fn validate_username(s: &str) -> bool {
    (4..=32).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric())
}

fn validate_password(s: &str) -> bool {
    (6..=32).contains(&s.len())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "`~!@#$%^&*()-_=+[{]}\\|;'\",<.>/?".contains(c))
}

#[post("/users/login", format = "application/json", data = "<user>")]
async fn login(
    user: Json<LoginUserInfo>,
    pk: &State<JWTPK>,
    redis: &State<RedisClient>,
) -> Result<Json<LoginResponse>, rocket::http::Status> {
    let mut conn = redis.client.get_tokio_connection().await.unwrap();

    let username: OptionalString = conn.get(k!("user:username")).await.unwrap();
    let username = username.into_inner();

    if username.as_ref() != Some(&user.username) {
        return Err(Status::Unauthorized);
    }

    let password: OptionalString = conn.get(k!("user:pass")).await.unwrap();
    let password = password.into_inner().unwrap();

    let result = rocket::tokio::task::block_in_place(|| {
        argon2::verify_encoded(&password, user.pass.as_bytes())
    });

    match result {
        Ok(true) => {}
        Ok(false) => return Err(Status::Unauthorized),
        Err(e) => {
            error!("{}", e);
            return Err(Status::InternalServerError);
        }
    }

    let key = ApiKey::create(user.username.clone(), &pk);

    Ok(Json(LoginResponse {
        token: key.auth_token.into_owned(),
    }))
}

#[derive(Debug, FromForm)]
struct MultipartFormData<'v> {
    #[field(validate = ext(ContentType::PNG))]
    #[field(validate = len(..128_i32.mebibytes()))]
    file: TempFile<'v>,
}

#[derive(Debug)]
pub struct ApiKey<'a> {
    auth_token: Cow<'a, str>,
    claims: Claims,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "::rocket::serde")]
pub struct Claims {
    sub: String,
    exp: i64,
}

impl<'a> ApiKey<'a> {
    fn create(user: String, pk: &JWTPK) -> Self {
        const JWT_EXPIRATION_HOURS: i64 = 24 * 30;

        let claims = Claims {
            sub: user,
            exp: (Utc::now() + Duration::hours(JWT_EXPIRATION_HOURS)).timestamp(),
        };

        let jwt = jsonwebtoken::encode(
            &jsonwebtoken::Header {
                alg: Algorithm::RS512,
                ..jsonwebtoken::Header::default()
            },
            &claims,
            &pk.k,
        )
        .unwrap();

        Self {
            auth_token: Cow::Owned(jwt),
            claims,
        }
    }

    fn from_token(token: &'a str, pubk: &JWTPUBK) -> Option<Self> {
        let mut validation = Validation::default();
        validation.algorithms = vec![Algorithm::RS512];
        let claims = jsonwebtoken::decode::<Claims>(token, &pubk.k, &validation)
            .ok()?
            .claims;
        Some(Self {
            auth_token: Cow::Borrowed(token),
            claims,
        })
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ApiKey<'r> {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let pubk = <&State<JWTPUBK>>::from_request(request).await.unwrap();

        request
            .headers()
            .get_one("Authorization")
            .and_then(|auth_token| {
                let token = auth_token.strip_prefix("Bearer ")?;
                ApiKey::from_token(token, pubk)
            })
            .into_outcome((
                Status::Unauthorized,
                "Authorization header missing or invalid",
            ))
    }
}

async fn compute_hash<P: AsRef<std::path::Path>>(p: P) -> Result<String, std::io::Error> {
    let mut ctxt = md5::Context::new();

    let mut file = tokio::fs::File::open(p).await?;
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        ctxt.consume(&buffer[..n]);
    }

    Ok(format!("{:x}", ctxt.compute()))
}

fn compute_hash_in_mem(data: &[u8]) -> String {
    let mut ctxt = md5::Context::new();
    ctxt.consume(data);
    format!("{:x}", ctxt.compute())
}

#[derive(Debug, Serialize)]
#[serde(crate = "::rocket::serde")]
struct UploadResponse {
    hash: String,
}

#[post("/media", format = "multipart/form-data", data = "<media>")]
async fn upload_media<'a>(
    _auth: ApiKey<'a>,
    mut media: Form<MultipartFormData<'a>>,
    file_root: &State<StaticFileRoot>,
) -> Json<UploadResponse> {
    let hash = match &media.file {
        TempFile::File { path, .. } => compute_hash(path).await.unwrap(),
        TempFile::Buffered { content, .. } => compute_hash_in_mem(content.as_bytes()),
    };

    let p = file_root.root.join(&hash);
    match media.file.persist_to(&p).await {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(18) /* 18 = EXDEV(Cross-device link) */ => {
            // copy file contents
            media.file.copy_to(&p).await.unwrap();
        }
        Err(e) => {
            panic!("{}", e);
        }
    };

    return Json(UploadResponse { hash });
}

struct JWTPK {
    k: jsonwebtoken::EncodingKey,
}

struct JWTPUBK {
    k: jsonwebtoken::DecodingKey,
}

struct StaticFileRoot {
    root: PathBuf,
}

struct KnownContentTypeFile {
    file: NamedFile,
    content_type: Option<&'static str>,
}

#[rocket::async_trait]
impl<'r, 'o: 'r> Responder<'r, 'o> for KnownContentTypeFile {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'o> {
        self.file.respond_to(request).map(|mut response| {
            if let Some(mime) = self.content_type {
                response.adjoin_header(ContentType(mime.parse().unwrap()));
            }

            response
        })
    }
}

#[get("/<hash>")]
async fn access_media_file(
    hash: &str,
    file_root: &State<StaticFileRoot>,
) -> Option<KnownContentTypeFile> {
    let p = file_root.root.join(hash);

    NamedFile::open(&p).await.ok().map(|file| {
        let content_type = tree_magic_mini::from_filepath(&p);
        KnownContentTypeFile { file, content_type }
    })
}

pub fn build() -> Rocket<Build> {
    let file_root =
        PathBuf::from(std::env::var("FILE_ROOT").unwrap_or_else(|_| "/srv/bk-media".into()));

    rocket::custom(rocket::config::Config {
        limits: Limits::new()
            .limit("file", 129.megabytes())
            .limit("data-form", 129.megabytes()),
        ..Config::default()
    })
    .mount("/", routes![index])
    .mount("/api/v1", routes![create_user, login, upload_media])
    .mount("/media", routes![access_media_file])
    // to set up keys:
    // mkdir crates/leafbk-media/src/keys
    // openssl genpkey -out crates/leafbk-media/src/keys/private.pem -algorithm RSA -pkeyopt rsa_keygen_bits:4096
    // openssl rsa -in crates/leafbk-media/src/keys/private.pem -pubout > crates/leafbk-media/src/keys/public.pub
    .manage(JWTPK {
        k: jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!("keys/private.pem")).unwrap(),
    })
    .manage(JWTPUBK {
        k: jsonwebtoken::DecodingKey::from_rsa_pem(include_bytes!("keys/public.pub")).unwrap(),
    })
    .manage(RedisClient {
        client: redis::Client::open("redis://127.0.0.1/").unwrap(),
    })
    .manage(StaticFileRoot { root: file_root })
}
