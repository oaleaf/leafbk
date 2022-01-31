#[macro_use]
extern crate rocket;

use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, Validation};
use rocket::data::{Limits, ToByteUnit};
use rocket::form::Form;
use rocket::fs::TempFile;
use rocket::http::{ContentType, Status};
use rocket::outcome::IntoOutcome;
use rocket::request::FromRequest;
use rocket::response::Responder;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::{request, Build, Config, Request, Rocket, State};
use std::borrow::Cow;

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
async fn create_user(user: Json<CreateUserInfo>, pk: &State<JWTPK>) -> Json<CreateUserResponse> {
    format!("{:?}", user);

    let user_id = "aaaa";

    let key = ApiKey::create(user_id.to_string(), &pk);

    Json(CreateUserResponse {
        token: key.auth_token.into_owned(),
    })
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

#[post("/users/login", format = "application/json", data = "<user>")]
async fn login(user: Json<LoginUserInfo>, pk: &State<JWTPK>) -> Json<LoginResponse> {
    format!("{:?}", user);

    let user_id = "aaaa";

    let key = ApiKey::create(user_id.to_string(), &pk);

    Json(LoginResponse {
        token: key.auth_token.into_owned(),
    })
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
    fn create(user_id: String, pk: &JWTPK) -> Self {
        const JWT_EXPIRATION_HOURS: i64 = 24 * 30;

        let claims = Claims {
            sub: user_id,
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

#[post("/media", format = "multipart/form-data", data = "<media>")]
async fn upload_media<'a>(
    auth: ApiKey<'a>,
    mut media: Form<MultipartFormData<'a>>,
) -> impl Responder<'a, 'a> + 'a {
    media
        .file
        .persist_to("/tmp/bk-media/input.bin")
        .await
        .unwrap();
    println!("{:?}", auth);

    "Hello"
}

struct JWTPK {
    k: jsonwebtoken::EncodingKey,
}

struct JWTPUBK {
    k: jsonwebtoken::DecodingKey,
}

pub fn build() -> Rocket<Build> {
    rocket::custom(rocket::config::Config {
        limits: Limits::new()
            .limit("file", 129.megabytes())
            .limit("data-form", 129.megabytes()),
        ..Config::default()
    })
    .mount("/", routes![index])
    .mount("/api/v1", routes![create_user, login, upload_media])
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
}
