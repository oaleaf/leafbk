#[macro_use]
extern crate rocket;

use rocket::fairing::AdHoc;
use rocket::figment::providers::{Env, Format, Serialized, Toml};
use rocket::figment::Figment;
use rocket::form::Form;
use rocket::http::Status;
use rocket::response::content::Html;
use rocket::response::{Redirect, Responder};
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::{Request, State};
use std::str::FromStr;
use url::Url;

use leafbk_auth::{ApiKey, JWTPUBK, _INTERNAL_JWTPK};
use leafbk_db::{OptionalString, RedisClient};

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "::rocket::serde")]
pub struct DeploymentLinks {
    pub auth: String,
    pub media: String,
}

impl Default for DeploymentLinks {
    fn default() -> Self {
        DeploymentLinks {
            auth: "http://localhost:8800".to_string(),
            media: "http://localhost:8801".to_string(),
        }
    }
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
    pk: &State<_INTERNAL_JWTPK>,
    redis: &State<RedisClient>,
) -> Result<Json<CreateUserResponse>, Status> {
    if !validate_username(&user.username) {
        return Err(Status::UnprocessableEntity);
    }

    if !validate_password(&user.pass) {
        return Err(Status::UnprocessableEntity);
    }

    let mut conn = redis.client.get_tokio_connection().await.unwrap();

    let v = leafbk_db::get!(&mut conn, "user:username", OptionalString, @unwrap).into_inner();

    if let Some(v) = v {
        warn!("User already registered: {}", v);
        return Err(Status::Conflict);
    }

    leafbk_db::set!(&mut conn, "user:username", user.0.username.clone(), (), @unwrap);

    const SALT: &[u8] = match option_env!("SALT") {
        Some(s) => s.as_bytes(),
        None => b"aaaaaaaaaaaa",
    };

    let hashed_pass = rocket::tokio::task::block_in_place(|| {
        argon2::hash_encoded(user.0.pass.as_bytes(), SALT, &ARGON_CFG)
    })
    .unwrap();

    leafbk_db::set!(&mut conn, "user:pass", hashed_pass, (), @unwrap);

    let key = ApiKey::create(user.username.clone(), &pk, vec!["leafbk-auth".to_string()]);

    Ok(Json(CreateUserResponse {
        token: key.into_string_owned(),
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
    pk: &State<_INTERNAL_JWTPK>,
    redis: &State<RedisClient>,
) -> Result<Json<LoginResponse>, rocket::http::Status> {
    let mut conn = redis.client.get_tokio_connection().await.unwrap();

    let username =
        leafbk_db::get!(&mut conn, "user:username", OptionalString, @unwrap).into_inner();

    if username.as_ref() != Some(&user.username) {
        return Err(Status::Unauthorized);
    }

    let password = leafbk_db::get!(&mut conn, "user:pass", String, @unwrap);

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

    let key = ApiKey::create(user.username.clone(), &pk, vec!["leafbk-auth".to_string()]);

    Ok(Json(LoginResponse {
        token: key.into_string_owned(),
    }))
}

#[derive(Debug, thiserror::Error)]
#[error("no such service")]
pub struct NoSuchService;

#[derive(Debug, Copy, Clone)]
pub enum Service {
    Media,
}

impl FromStr for Service {
    type Err = NoSuchService;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let result = match s {
            "media" => Service::Media,
            _ => return Err(NoSuchService),
        };

        Ok(result)
    }
}

impl Service {
    pub fn name(self) -> &'static str {
        match self {
            Service::Media => "leafbk-media",
        }
    }

    pub fn url_from(self, d: &DeploymentLinks) -> Url {
        match self {
            Service::Media => d.media.parse().unwrap(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnterError {
    #[error("invalid token")]
    InvalidToken,
    #[error("no such service")]
    NoSuchService(#[from] NoSuchService),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for EnterError {
    fn respond_to(self, _request: &'r Request<'_>) -> rocket::response::Result<'o> {
        let status = match self {
            EnterError::InvalidToken => Status::Unauthorized,
            EnterError::NoSuchService(_) => Status::NotFound,
        };
        rocket::response::Result::Err(status)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthConfirmError {
    #[error("no such service")]
    NoSuchService(#[from] NoSuchService),
}

impl<'r, 'o: 'r> Responder<'r, 'o> for AuthConfirmError {
    fn respond_to(self, _request: &'r Request<'_>) -> rocket::response::Result<'o> {
        let status = match self {
            AuthConfirmError::NoSuchService(_) => Status::NotFound,
        };
        rocket::response::Result::Err(status)
    }
}

#[get("/auth/confirmation_form?<service>&<state>")]
pub fn auth_confirm(service: &str, state: Option<&str>) -> Result<Html<String>, AuthConfirmError> {
    let state = state.unwrap_or("no_state");

    let _ = service.parse::<Service>()?;

    Ok(Html(format!(
        // language=HTML
        r#"
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />

                <title>Confirm</title>
                <script>
                    window.addEventListener('DOMContentLoaded', (event) => {{
                        let token = localStorage.getItem("token");
                        if (!token) {{
                            window.close();
                        }}
                        
                        document.getElementById("token-input").value = token;
                    }});
                </script>
            </head>
            <body>
                <h1>Confirm</h1>
                <form action="/auth/confirm" method="post">
                    <input type="hidden" name="service" value="{service}" />
                    <input type="hidden" name="state" value="{state}" />
                    <input type="hidden" name="token" id="token-input" />
                    <input type="submit" value="Confirm" />
                </form>
            </body>
            </html>
        "#
    )))
}

#[derive(Debug, FromForm)]
pub struct EnterForm {
    service: String,
    state: String,
    token: String,
}

#[post("/auth/confirm", data = "<data>")]
pub fn enter(
    data: Form<EnterForm>,
    pk: &State<_INTERNAL_JWTPK>,
    pubk: &State<JWTPUBK>,
    depl: &State<DeploymentLinks>,
) -> Result<Redirect, EnterError> {
    let EnterForm {
        service,
        state,
        token,
    } = data.into_inner();

    let token = ApiKey::from_token(&token, pubk).ok_or(EnterError::InvalidToken)?;

    let service = service.parse::<Service>()?;

    let mut service_url = service.url_from(depl);
    let serv_name = service.name();

    let token = ApiKey::create(token.get_sub().to_string(), pk, vec![serv_name.to_string()]);

    service_url.set_path("auth");
    {
        let mut qp = service_url.query_pairs_mut();
        qp.append_pair("code", token.as_str());
        qp.append_pair("state", &state);
    }

    Ok(Redirect::to(service_url.to_string()))
}

#[launch]
fn rocket() -> _ {
    let figment = Figment::from(rocket::Config {
        port: 8800,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(DeploymentLinks::default()))
    .merge(Toml::file("leafbk-auth.toml").nested())
    .merge(Env::prefixed("LEAFBK_AUTH_"));
    let rk = rocket::custom(figment);
    let rk = leafbk_auth::config_rocket(rk);

    // see leafbk_auth::config_rocket for setting up the keys
    let rk = rk.manage(_INTERNAL_JWTPK::new(
        jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!("keys/private.pem")).unwrap(),
    ));
    let rk = rk.manage(RedisClient {
        client: leafbk_db::redis::Client::open("redis://127.0.0.1/").unwrap(),
    });
    rk.mount("/", routes![create_user, login])
        .mount("/", routes![auth_confirm, enter])
        .attach(AdHoc::config::<DeploymentLinks>())
}
