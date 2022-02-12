use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, Validation};
use rocket::http::{HeaderMap, Status};
use rocket::outcome::IntoOutcome;
use rocket::request::FromRequest;
use rocket::serde::{Deserialize, Serialize};
use rocket::{request, Build, Request, Rocket, State};
use std::borrow::Cow;

#[derive(Debug)]
pub struct ApiKey<'a> {
    auth_token: Cow<'a, str>,
    claims: Claims,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "::rocket::serde")]
pub struct Claims {
    sub: String,
    iss: String,
    exp: i64,
    aud: Vec<String>,
}

impl<'a> ApiKey<'a> {
    fn new(auth_token: impl Into<Cow<'a, str>>, claims: Claims) -> Self {
        ApiKey {
            auth_token: auth_token.into(),
            claims,
        }
    }

    pub fn as_str(&self) -> &str {
        self.auth_token.as_ref()
    }

    pub fn into_string_owned(self) -> String {
        self.auth_token.into_owned()
    }

    pub fn get_sub(&self) -> &str {
        &self.claims.sub
    }

    pub fn create(user: String, pk: &_INTERNAL_JWTPK, aud: Vec<String>) -> Self {
        let claims = Self::create_claims_for_user(user, aud);
        let jwt = Self::create_jwt(&pk, &claims);

        Self::new(jwt, claims)
    }

    fn create_claims_for_user(user: String, aud: Vec<String>) -> Claims {
        const JWT_EXPIRATION_HOURS: i64 = 24 * 30;

        Claims {
            sub: user,
            iss: "leafbk-auth".to_string(),
            exp: (Utc::now() + Duration::hours(JWT_EXPIRATION_HOURS)).timestamp(),
            aud,
        }
    }

    fn create_jwt(pk: &_INTERNAL_JWTPK, claims: &Claims) -> String {
        let jwt_header = jsonwebtoken::Header {
            alg: Algorithm::RS512,
            ..jsonwebtoken::Header::default()
        };

        jsonwebtoken::encode(&jwt_header, claims, &pk.k).unwrap()
    }

    fn from_headers(headers: &'a HeaderMap, pubk: &JWTPUBK) -> Option<Self> {
        headers.get_one("Authorization").and_then(|auth_token| {
            let token = auth_token.strip_prefix("Bearer ")?;
            ApiKey::from_token(token, pubk)
        })
    }

    pub fn from_token(token: &'a str, pubk: &JWTPUBK) -> Option<Self> {
        let claims = Self::claims_from_token(token, pubk)?;
        Some(Self::new(token, claims))
    }

    fn claims_from_token(token: &str, pubk: &JWTPUBK) -> Option<Claims> {
        let validation = Self::create_validation();

        jsonwebtoken::decode::<Claims>(token, &pubk.k, &validation)
            .ok()
            .map(|it| it.claims)
    }

    fn create_validation() -> Validation {
        let mut validation = Validation::default();
        validation.algorithms = vec![Algorithm::RS512];
        validation
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ApiKey<'r> {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let pubk = <&State<JWTPUBK>>::from_request(request).await.unwrap();

        ApiKey::from_headers(request.headers(), pubk).into_outcome((
            Status::Unauthorized,
            "Authorization header missing or invalid",
        ))
    }
}

#[allow(non_camel_case_types)]
pub struct _INTERNAL_JWTPK {
    k: jsonwebtoken::EncodingKey,
}

impl _INTERNAL_JWTPK {
    pub fn new(k: jsonwebtoken::EncodingKey) -> Self {
        Self { k }
    }
}

pub struct JWTPUBK {
    k: jsonwebtoken::DecodingKey,
}

pub fn config_rocket(rocket: Rocket<Build>) -> Rocket<Build> {
    // to set up keys:

    // mkdir crates/leafbk-auth/src/keys
    // openssl genpkey -out crates/leafbk-auth/src/keys/private.pem -algorithm RSA -pkeyopt rsa_keygen_bits:4096
    // openssl rsa -in crates/leafbk-auth/src/keys/private.pem -pubout > crates/leafbk-auth/src/keys/public.pub

    rocket.manage(JWTPUBK {
        k: jsonwebtoken::DecodingKey::from_rsa_pem(include_bytes!("keys/public.pub")).unwrap(),
    })
}
