#[macro_use]
extern crate rocket;

use leafbk_auth::ApiKey;
use leafbk_db::{redis, RedisClient};
use rocket::data::{Limits, ToByteUnit};
use rocket::fairing::AdHoc;
use rocket::figment::providers::{Env, Format, Serialized, Toml};
use rocket::figment::Figment;
use rocket::form::Form;
use rocket::fs::{NamedFile, TempFile};
use rocket::http::ContentType;
use rocket::response::Responder;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::io::AsyncReadExt;
use rocket::{tokio, Build, Request, Rocket, State};
use std::path::PathBuf;

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

#[derive(Debug, FromForm)]
struct MultipartFormData<'v> {
    #[field(validate = len(..128_i32.mebibytes()))]
    file: TempFile<'v>,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(crate = "::rocket::serde")]
struct StaticFileRoot {
    #[serde(rename = "static_file_root")]
    root: PathBuf,
}

impl Default for StaticFileRoot {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/srv/leafbk-media"),
        }
    }
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

    match NamedFile::open(&p).await {
        Ok(file) => {
            let content_type =
                tokio::task::spawn_blocking(move || tree_magic_mini::from_filepath(&p))
                    .await
                    .unwrap();
            Some(KnownContentTypeFile { file, content_type })
        }
        Err(_) => None,
    }
}

#[get("/auth")]
fn auth() -> &'static str {
    "Hello. Try uploading with the token now"
}

pub fn build() -> Rocket<Build> {
    let config = Figment::from(rocket::Config {
        limits: Limits::new()
            .limit("file", 129.megabytes())
            .limit("data-form", 129.megabytes()),
        port: 8801,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(StaticFileRoot::default()))
    .merge(Toml::file("leafbk-media.toml").nested())
    .merge(Env::prefixed("LEAFBK_MEDIA_"));

    let rk = rocket::custom(config);

    let rk = rk.manage(RedisClient {
        client: redis::Client::open("redis://127.0.0.1/").unwrap(),
    });

    rk.mount("/api/v1", routes![upload_media])
        .mount("/media", routes![access_media_file])
        .mount("/", routes![auth])
        .attach(AdHoc::config::<StaticFileRoot>())
}
