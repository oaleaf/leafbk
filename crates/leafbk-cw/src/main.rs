use leafbk_auth::ApiKey;
use rocket::fairing::AdHoc;
use rocket::figment::providers::{Env, Format, Serialized, Toml};
use rocket::figment::Figment;
use rocket::request::FromParam;
use rocket::response::content::Html;
use rocket::response::stream::{Event, EventStream};
use rocket::serde::{Deserialize, Serialize};
use rocket::tokio::select;
use rocket::tokio::sync::broadcast::{channel, error::RecvError, Sender};
use rocket::tokio::sync::Mutex;
use rocket::{get, put, routes, Shutdown, State};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug)]
#[serde(crate = "rocket::serde")]
struct CwConfig {}

impl Default for CwConfig {
    fn default() -> Self {
        Self {}
    }
}

struct FileData {
    content: String,
    subscriber: Sender<FileEvent>,
}

#[derive(Clone, Serialize)]
#[serde(crate = "rocket::serde")]
enum FileEvent {
    Update(String),
}

struct Files {
    files: BTreeMap<String, FileData>,
}

const CHANNEL_BUFFER_SIZE: usize = 64;

impl Files {
    fn get_or_insert(&mut self, name: &str) -> &mut FileData {
        self.files
            .entry(name.to_string())
            .or_insert_with(|| FileData {
                content: String::new(),
                subscriber: channel(CHANNEL_BUFFER_SIZE).0,
            })
    }
}

struct FileName<'a>(&'a str);

#[derive(Debug)]
struct InvalidFileName;

impl<'a> FromParam<'a> for FileName<'a> {
    type Error = InvalidFileName;

    fn from_param(param: &'a str) -> Result<Self, Self::Error> {
        if param.contains(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
            Err(InvalidFileName)
        } else {
            Ok(FileName(param))
        }
    }
}

#[inline]
pub fn escape_html(input: &str) -> String {
    let mut output = String::with_capacity(input.len() * 2);
    for c in input.chars() {
        match c {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#x27;"),
            '/' => output.push_str("&#x2F;"),
            // Additional one for old IE (unpatched IE8 and below)
            // See https://github.com/OWASP/owasp-java-encoder/wiki/Grave-Accent-Issue
            '`' => output.push_str("&#96;"),
            _ => output.push(c),
        }
    }

    // Not using shrink_to_fit() on purpose
    output
}

#[get("/<name>")]
async fn editor(name: FileName<'_>, files: &State<Arc<Mutex<Files>>>) -> Html<String> {
    let name = name.0;

    let html = {
        let mut lock = files.lock().await;
        let file = lock.get_or_insert(name);
        let content = &file.content;
        let content = escape_html(content);

        format!(
            // language=html
            r#"
            <!DOCTYPE html>
            <html>
                <head>
                    <meta charset="utf-8">
                    <title>{name} | cw.oaleaf.dev</title>

                    <style>
                        html, body {{
                            height: 100%;
                            margin: 0;
                        }}

                        * {{
                            font-family: monospace;
                            font-size: 14px;
                        }}
                        
                        #editor {{
                            width: 98%;
                            height: 90%;
                            margin: 0;
                        }}

                        #token-input {{
                            width: 98%;
                            height: 6%;
                            margin: 0;
                        }}
                    </style>
                </head>
                <body>
                    <textarea id="editor" oninput="changed()" readonly>{content}</textarea>
                    <input id="token-input" oninput="tokenChanged()"/>
                    
                    <script>
                        let eventSource = new EventSource("/{name}/events");
                        let lastInput = new Date() - 2;
                        eventSource.onmessage = (e) => {{
                            console.log(e);
                            let data = JSON.parse(e.data);
                            if (data.Update && lastInput + 2 < new Date()) {{
                                document.getElementById("editor").value = data.Update;
                            }}
                        }};
                        
                        const changed = () => {{
                            let data = document.getElementById("editor").value;
                            let token = document.getElementById("token-input").value;
                            
                            if (token !== '') {{
                                fetch('/{name}/content', {{
                                    method: 'PUT',
                                    headers: {{
                                        'Authorization': 'Bearer ' + token
                                    }},
                                    body: data,
                                }});
                                
                                lastInput = new Date();
                            }}
                        }};
                        
                        const tokenChanged = () => {{
                            let token = document.getElementById("token-input").value;
                            if (token !== '') {{
                                document.getElementById("editor").removeAttribute("readonly");
                            }} else {{
                                document.getElementById("editor").setAttribute("readonly", "true");
                            }}
                        }}
                    </script>
                </body>
            </html>
            "#
        )
    };

    Html(html)
}

#[get("/<name>/events")]
async fn subscribe_events(
    name: FileName<'_>,
    files: &State<Arc<Mutex<Files>>>,
    mut end: Shutdown,
) -> EventStream![] {
    let name = name.0;

    let mut rx = files
        .lock()
        .await
        .get_or_insert(name)
        .subscriber
        .subscribe();

    EventStream! {
        loop {
            let msg = select! {
                msg = rx.recv() => match msg {
                    Ok(msg) => msg,
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(_)) => continue,
                },
                _ = &mut end => break,
            };

            yield Event::json(&msg);
        }
    }
}

#[get("/<name>/content")]
async fn get_content(name: FileName<'_>, files: &State<Arc<Mutex<Files>>>) -> String {
    files.lock().await.get_or_insert(name.0).content.clone()
}

#[put("/<name>/content", data = "<content>")]
async fn update_content(
    _k: ApiKey<'_>,
    name: FileName<'_>,
    content: String,
    files: &State<Arc<Mutex<Files>>>,
) {
    let name = name.0;

    let mut files = files.lock().await;
    let file = files.get_or_insert(name);

    file.content = content;
    let _ = file
        .subscriber
        .send(FileEvent::Update(file.content.clone()));
}

#[rocket::launch]
fn rocket() -> _ {
    let figment = Figment::from(rocket::Config {
        port: 8802,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(CwConfig::default()))
    .merge(Toml::file("leafbk-cw.toml").nested())
    .merge(Env::prefixed("LEAFBK_CW_"));

    let rk = rocket::custom(figment);

    let rk = leafbk_auth::config_rocket(rk);

    rk.mount(
        "/",
        routes![editor, get_content, subscribe_events, update_content],
    )
    .manage(Arc::new(Mutex::new(Files {
        files: BTreeMap::new(),
    })))
    .attach(AdHoc::config::<CwConfig>())
}
