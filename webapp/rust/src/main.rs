extern crate bytes;
extern crate mysql;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate log;
extern crate actix_web;
extern crate chrono;
extern crate env_logger;
extern crate failure;
extern crate futures;
extern crate handlebars;
extern crate rand;
extern crate serde;
extern crate sha1;
extern crate tempfile;

use actix_web::error::Error;
use actix_web::fs::StaticFiles;
use actix_web::http::{Method, StatusCode};
use actix_web::middleware::session::{
    CookieSessionBackend, RequestSession, Session, SessionStorage,
};
use actix_web::{
    server, App, Form, FutureResponse, HttpMessage, HttpRequest, HttpResponse, Path, Query, State,
};
use chrono::NaiveDateTime;
use failure::Error as FailureError;
use futures::prelude::*;
use handlebars::Handlebars;
use mysql as my;
use mysql::prelude::*;
use rand::distributions::Alphanumeric;
use rand::prelude::*;
use sha1::{Digest, Sha1};
use std::ffi::OsStr;
use std::io::prelude::*;
use std::sync::Arc;

const SESSION_KEY: &str = "tonymoris";
const AVATAR_MAX_SIZE: u64 = 1 * 1024 * 1024;

#[derive(Clone)]
struct Isu {
    pool: my::Pool,
    templates: Arc<Handlebars>,
}

#[derive(Default, Serialize, Deserialize, Debug, Clone, Copy)]
struct UserSession {
    user_id: u64,
}

// nameやsaltなどはNOT NULL制約はついていないがコード上NOT NULLとして扱われていたのでOptionをつけなかった
#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    id: u64,
    name: String,
    salt: String,
    password: String,
    display_name: String,
    avatar_icon: String,
    created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Channel {
    id: u64,
    name: String,
    description: Option<String>,
    updated_at: NaiveDateTime,
    created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Message {
    id: u64,
    channel_id: u64,
    user_id: u64,
    content: String,
    created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HaveRead {
    user_id: u64,
    channel_id: u64,
    message_id: u64,
    updated_at: NaiveDateTime,
    created_at: NaiveDateTime,
}

#[derive(Deserialize)]
struct ParamChannelId {
    channel_id: u64,
}

#[derive(Deserialize)]
struct ParamPage {
    page: Option<u64>,
}

#[derive(Deserialize)]
struct ParamUserName {
    user_name: String,
}
#[derive(Deserialize)]
struct ParamRegister {
    name: String,
    password: String,
}
#[derive(Deserialize)]
struct ParamChannel {
    name: String,
    description: String,
}
#[derive(Deserialize)]
struct ParamFilename {
    file_name: String,
}

#[derive(Deserialize)]
struct ParamNewMessage {
    channel_id: u64,
    message: String,
}
#[derive(Deserialize)]
struct ParamMessage {
    channel_id: u64,
    last_message_id: u64,
}

impl FromRow for User {
    fn from_row(row: my::Row) -> Self {
        Self::from_row_opt(row).expect("failed to deserialize data")
    }

    fn from_row_opt(row: my::Row) -> Result<Self, my::FromRowError> {
        FromRow::from_row_opt(row).map(
            |(id, name, salt, password, display_name, avatar_icon, created_at)| Self {
                id,
                name,
                salt,
                password,
                display_name,
                avatar_icon,
                created_at,
            },
        )
    }
}

impl FromRow for Channel {
    fn from_row(row: my::Row) -> Self {
        Self::from_row_opt(row).expect("failed to deserialize data")
    }

    fn from_row_opt(row: my::Row) -> Result<Self, my::FromRowError> {
        FromRow::from_row_opt(row).map(|(id, name, description, updated_at, created_at)| Self {
            id,
            name,
            description,
            updated_at,
            created_at,
        })
    }
}

impl FromRow for Message {
    fn from_row(row: my::Row) -> Self {
        Self::from_row_opt(row).expect("failed to deserialize data")
    }

    fn from_row_opt(row: my::Row) -> Result<Self, my::FromRowError> {
        FromRow::from_row_opt(row).map(|(id, channel_id, user_id, content, created_at)| Self {
            id,
            channel_id,
            user_id,
            content,
            created_at,
        })
    }
}

impl FromRow for HaveRead {
    fn from_row(row: my::Row) -> Self {
        Self::from_row_opt(row).expect("failed to deserialize data")
    }

    fn from_row_opt(row: my::Row) -> Result<Self, my::FromRowError> {
        FromRow::from_row_opt(row).map(
            |(user_id, channel_id, message_id, updated_at, created_at)| Self {
                user_id,
                channel_id,
                message_id,
                updated_at,
                created_at,
            },
        )
    }
}

impl Isu {
    fn new() -> Self {
        let pool = my::Pool::new("mysql://isucon:isucon@localhost:3306/isubata")
            .expect("failed to create mysql pool");
        let mut templates = Handlebars::new();
        for (name, tmpl) in vec![
            ("add_channel", include_str!("../views/add_channel.tmpl")),
            ("channel", include_str!("../views/channel.tmpl")),
            ("history", include_str!("../views/history.tmpl")),
            ("index", include_str!("../views/index.tmpl")),
            ("layout", include_str!("../views/layout.tmpl")),
            ("login", include_str!("../views/login.tmpl")),
            ("profile", include_str!("../views/profile.tmpl")),
            ("register", include_str!("../views/register.tmpl")),
        ] {
            templates
                .register_template_string(name, tmpl)
                .expect("failed to register template");
        }

        let ret = Self {
            pool,
            templates: Arc::new(templates),
        };

        ret.exec_sql(
            r#"SET SESSION sql_mode='TRADITIONAL,NO_AUTO_VALUE_ON_ZERO,ONLY_FULL_GROUP_BY'"#,
            (),
        ).expect("sql failed");
        ret
    }
    fn exec_sql(&self, sql: impl AsRef<str>, param: impl Into<my::Params>) -> Result<(), Error> {
        self.pool
            .prep_exec(sql.as_ref(), param)
            .map(|_| ())
            .map_err(err)
    }

    fn query_sql<T: FromRow>(
        &self,
        sql: impl AsRef<str>,
        param: impl Into<my::Params>,
    ) -> Result<Vec<T>, Error> {
        self.pool
            .prep_exec(sql, param)
            .map_err(err)?
            .map(|ret| ret.map(T::from_row))
            .collect::<Result<Vec<T>, _>>()
            .map_err(err)
    }

    fn first_sql<T: FromRow>(
        &self,
        sql: impl AsRef<str>,
        param: impl Into<my::Params>,
    ) -> Result<Option<T>, Error> {
        self.pool
            .first_exec(sql, param)
            .map_err(err)
            .map(|opt| opt.map(T::from_row))
    }

    fn render(&self, name: &str, data: &serde_json::Value) -> Result<String, Error> {
        self.templates.render(name, data).map_err(err)
    }

    fn user(&self, session: Session) -> Result<Option<User>, Error> {
        match session.get::<UserSession>(SESSION_KEY) {
            Ok(None) => Ok(None),
            Ok(Some(us)) => self.db_get_user(us.user_id),
            Err(e) => Err(e),
        }
    }

    fn db_get_user(&self, user_id: u64) -> Result<Option<User>, Error> {
        self.first_sql("SELECT * FROM user WHERE id = ?", (user_id,))
    }

    fn db_add_message<'a, 's>(
        &'a self,
        channel_id: u64,
        user_id: u64,
        content: &'s str,
    ) -> Result<(), Error> {
        self.exec_sql("INSERT INTO message (channel_id, user_id, content, created_at) VALUES (?, ?, ?, NOW())", (channel_id, user_id, content))
    }

    fn get_channel_list_info(
        &self,
        focus_channel_id: impl Into<Option<u64>>,
    ) -> Result<(Vec<Channel>, String), Error> {
        let focus_channel_id = focus_channel_id.into();
        let channels: Vec<Channel> = self.query_sql("SELECT * FROM channel ORDER BY id", ())?;
        let description = channels
            .iter()
            .find(|ch| Some(ch.id) == focus_channel_id)
            .and_then(|ch| ch.description.clone())
            .unwrap_or_else(|| "".into());
        Ok((channels, description))
    }

    fn random_string(&self, n: usize) -> String {
        use std::iter;

        let mut rng = thread_rng();
        iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(n)
            .collect()
    }

    fn register(&self, user: &str, password: &str) -> Result<u64, my::Error> {
        let salt = self.random_string(20);
        let pass_digest = format!("{:x}", Sha1::digest_str(&(salt.clone() + password)));
        self.pool.prep_exec("INSERT INTO user (name, salt, password, display_name, avatar_icon, created_at) VALUES (?, ?, ?, ?, ?, NOW())", (user, salt, pass_digest, user, "default.png"))?;
        let result = self.pool
            .prep_exec("SELECT LAST_INSERT_ID() AS last_insert_id", ())?;
        Ok(result.last_insert_id())
    }
}

fn ext2mime<'a>(ext: &'a str) -> Option<&'static str> {
    match ext {
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "gif" => Some("image/gif"),
        _ => None,
    }
}

fn err(e: impl ::failure::Fail) -> Error {
    let e: FailureError = e.into();
    e.into()
}

fn http_ok(body: String) -> HttpResponse {
    HttpResponse::Ok().body(body)
}

fn http_redirect(path: &str, status: u16) -> HttpResponse {
    let status = StatusCode::from_u16(status).expect("invalide status given");
    HttpResponse::build(status)
        .header("Location", path)
        .finish()
}

fn http_status(status: u16) -> HttpResponse {
    let status = StatusCode::from_u16(status).expect("invalide status given");
    HttpResponse::build(status).finish()
}

fn app(isu: Isu) -> App<Isu> {
    let mut app: App<Isu> = App::with_state(isu);

    app = app.middleware(SessionStorage::new(
        CookieSessionBackend::signed(&[0; 32]).secure(false),
    ));

    app = app.handler(
        "/css",
        StaticFiles::new("/home/isucon/isubata/webapp/public/css")
            .unwrap()
            .show_files_listing(),
    );
    app = app.handler(
        "/js",
        StaticFiles::new("/home/isucon/isubata/webapp/public/js")
            .unwrap()
            .show_files_listing(),
    );
    app = app.handler(
        "/fonts",
        StaticFiles::new("/home/isucon/isubata/webapp/public/fonts")
            .unwrap()
            .show_files_listing(),
    );

    app = app.route(
        "/initialize",
        Method::GET,
        |state: State<Isu>| -> Result<HttpResponse, Error> {
            state.exec_sql("DELETE FROM user WHERE id > 1000", ())?;
            state.exec_sql("DELETE FROM user WHERE id > 1000", ())?;
            state.exec_sql("DELETE FROM image WHERE id > 1001", ())?;
            state.exec_sql("DELETE FROM channel WHERE id > 10", ())?;
            state.exec_sql("DELETE FROM message WHERE id > 10000", ())?;
            state.exec_sql("DELETE FROM haveread", ())?;
            Ok(http_status(204))
        },
    );

    app = app.route(
        "/",
        Method::GET,
        |state: State<Isu>, req: HttpRequest<Isu>| -> Result<HttpResponse, Error> {
            match req.session().get::<UserSession>(SESSION_KEY)? {
                Some(_user) => Ok(http_redirect("/channel/1", 303)),
                None => state.render("index", &json!({})).map(http_ok),
            }
        },
    );

    app = app.route(
        "/channel/{channel_id}",
        Method::GET,
        |state: State<Isu>,
         session: Session,
         path: Path<ParamChannelId>|
         -> Result<HttpResponse, Error> {
            let user = state.user(session)?;
            match user {
                None => Ok(http_redirect("/login", 303)),
                Some(user) => {
                    let channel_id = path.channel_id;
                    let (channels, description) = state.get_channel_list_info(channel_id)?;
                    state
                        .render(
                            "channel",
                            &json!({
                                "channel_id": channel_id,
                                "channels": channels,
                                "description": description,
                                "user": user}),
                        )
                        .map(http_ok)
                }
            }
        },
    );

    app = app.route(
        "/register",
        Method::GET,
        |state: State<Isu>| -> Result<HttpResponse, Error> {
            state.render("register", &json!({})).map(http_ok)
        },
    );

    app = app.route(
        "/register",
        Method::POST,
        |state: State<Isu>,
         session: Session,
         form: Form<ParamRegister>|
         -> Result<HttpResponse, Error> {
            let name = &form.name;
            let pw = &form.password;
            if name == "" || pw == "" {
                return Ok(http_status(400));
            }
            match state.register(name, pw) {
                Ok(user_id) => session
                    .set(SESSION_KEY, UserSession { user_id })
                    .map(|_| http_redirect("/", 303)),
                Err(my::Error::MySqlError(my::MySqlError { code: 1062, .. })) => {
                    Ok(http_status(409))
                }
                Err(other) => Err(err(other)),
            }
        },
    );

    app = app.route(
        "/login",
        Method::GET,
        |state: State<Isu>| -> Result<HttpResponse, Error> {
            state.render("login", &json!({})).map(http_ok)
        },
    );

    app = app.route(
        "/login",
        Method::POST,
        |state: State<Isu>,
         session: Session,
         form: Form<ParamRegister>|
         -> Result<HttpResponse, Error> {
            let name = &form.name;
            let password = &form.password;
            let user: User = match state.first_sql("SELECT * FROM user WHERE name = ?", (name,))? {
                None => return Ok(http_status(403)),
                Some(user) => user,
            };
            if user.password != format!("{:x}", Sha1::digest_str(&(user.salt + password))) {
                Ok(http_status(403))
            } else {
                session
                    .set(SESSION_KEY, UserSession { user_id: user.id })
                    .map(|_| http_redirect("/", 303))
            }
        },
    );

    app = app.route(
        "/logout",
        Method::GET,
        |session: Session| -> Result<HttpResponse, Error> {
            session.clear();
            Ok(http_redirect("/", 303))
        },
    );

    app = app.route(
        "/message",
        Method::POST,
        |state: State<Isu>,
         session: Session,
         form: Form<ParamNewMessage>|
         -> Result<HttpResponse, Error> {
            let user_id = match session.get::<UserSession>(SESSION_KEY)? {
                None => return Ok(http_status(403)),
                Some(UserSession { user_id }) => user_id,
            };
            let channel_id = form.channel_id;
            let message = &form.message;
            state.db_add_message(channel_id, user_id, message)?;
            Ok(http_status(204))
        },
    );

    app = app.route(
        "/message",
        Method::GET,
        |state: State<Isu>,
         session: Session,
         query: Query<ParamMessage>|
         -> Result<HttpResponse, Error> {
            let user_id = match session.get::<UserSession>(SESSION_KEY)? {
                None => return Ok(http_status(403)),
                Some(UserSession { user_id }) => user_id,
            };
            let channel_id = query.channel_id;
            let last_message_id = query.last_message_id;
            let messages: Vec<Message> = state.query_sql(
                "SELECT * FROM message WHERE id > ? AND channel_id = ? ORDER BY id DESC LIMIT 100",
                (last_message_id, channel_id),
            )?;
            let max_message_id = messages.iter().map(|row| row.id).max().unwrap_or(0);
            let response = messages
                .into_iter()
                .map(|message| {
                    let (name, display_name, avatar_icon): (
                        String,
                        String,
                        String,
                    ) = state
                        .first_sql(
                            "SELECT name, display_name, avatar_icon FROM user WHERE id = ?",
                            (message.user_id,),
                        )
                        .map(|opt| opt.expect("application reached inconsistent state"))?;
                    Ok(json!({
                        "id": message.id,
                        "user": {"name": name, "display_name": display_name, "avatar_icon": avatar_icon},
                        "date": message
                            .created_at
                            .format("%Y/%m/%d %H:%M:%S")
                            .to_string(),
                        "content":message.content
                    }))
                })
                .rev()
                .collect::<Result<Vec<_>, Error>>()?;

            state.exec_sql(
                "INSERT INTO haveread (user_id, channel_id, message_id, updated_at, created_at) \
                 VALUES (?, ?, ?, NOW(), NOW()) \
                 ON DUPLICATE KEY UPDATE message_id = ?, updated_at = NOW()",
                (user_id, channel_id, max_message_id, max_message_id),
            )?;

            Ok(HttpResponse::Ok().json(response))
        },
    );

    app = app.route(
        "/fetch",
        Method::GET,
        |state: State<Isu>, session: Session| -> Result<HttpResponse, Error> {
            use std::thread::sleep;
            use std::time::Duration;
            let user_id = match session.get::<UserSession>(SESSION_KEY)? {
                None => return Ok(http_status(403)),
                Some(UserSession { user_id }) => user_id,
            };
            sleep(Duration::from_secs(1));

            let channel_ids: Vec<u64> = state.query_sql("SELECT id FROM channel", ())?;
            let res = channel_ids
                .into_iter()
                .map(|channel_id| {
                    let have_read: Option<HaveRead> = state.first_sql(
                        "SELECT * FROM haveread WHERE user_id = ? AND channel_id = ?",
                        (user_id, channel_id),
                    )?;
                    Ok(json!({
                        "channel_id": channel_id,
                        "unread": match have_read {
                            None => state
                                .first_sql(
                                    "SELECT COUNT(*) as cnt FROM message WHERE channel_id = ?",
                                    (channel_id,),
                                )
                                .map(|opt: Option<u64>| opt.expect("COUNT must have a value"))?,
                            Some(have_read) => state
                                .first_sql(
                                    "SELECT COUNT(*) as cnt FROM message WHERE channel_id = ? AND ? < id",
                                    (channel_id, have_read.message_id),
                                )
                                .map(|opt: Option<u64>| opt.expect("COUNT must have a value"))?,
                        }
                    }))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(HttpResponse::Ok().json(res))
        },
    );

    app = app.route(
        "/history/{channel_id}",
        Method::GET,
        |state: State<Isu>,
         session: Session,
         path: Path<ParamChannelId>,
         query: Query<ParamPage>|
         -> Result<HttpResponse, Error> {
            let user = match state.user(session)? {
                None => return Ok(http_redirect("/login", 303)),
                Some(user) => user,
            };
            let channel_id = path.channel_id;
            let page = query.page.unwrap_or(1);
            if page == 0 {
                return Ok(http_status(400));
            }
            let n = 20;
            let rows: Vec<Message> = state.query_sql(
                "SELECT * FROM message WHERE channel_id = ? ORDER BY id DESC LIMIT ? OFFSET ?",
                (channel_id, n, (page - 1) * n),
            )?;
            let messages = rows.into_iter()
                .map(|row| {
                    let (name, display_name, avatar_icon): (
                        String,
                        String,
                        String,
                    ) = state
                        .first_sql(
                            "SELECT name, display_name, avatar_icon FROM user WHERE id = ?",
                            (row.user_id,),
                        )
                        .map(|opt| opt.expect("application reached inconsistent state"))?;
                    Ok(json!({
                         "id": row.id,
                         "user": {"name": name, "display_name": display_name, "avatar_icon": avatar_icon},
                         "date": row.created_at
                             .format("%Y/%m/%d %H:%M:%S")
                             .to_string(),
                         "content": row.content,
                     }))
                })
                .rev()
                .collect::<Result<Vec<_>, Error>>()?;

            let cnt = state
                .first_sql(
                    "SELECT COUNT(*) as cnt FROM message WHERE channel_id = ?",
                    (channel_id,),
                )
                .map(|opt: Option<u64>| opt.expect("COUNT must have a value"))?;
            let max_page = if cnt == 0 {
                1
            } else {
                (((cnt as f64) / (n as f64)).ceil()) as u64
            };

            if page > max_page {
                return Ok(http_status(400));
            }
            let (channels, description) = state.get_channel_list_info(channel_id)?;
            state
                .render(
                    "history",
                    &json!({
                        "user": user,
                        "messages": messages,
                        "page": page,
                        "max_page": max_page,
                        "channel_id": channel_id,
                        "channels": channels,
                        "description": description,
                        // rust only
                        "index": (1..=max_page).collect::<Vec<u64>>(),
                        "page_minus": page - 1,
                        "page_plus": page + 1,
                    }),
                )
                .map(http_ok)
        },
    );

    app = app.route(
        "/profile/{user_name}",
        Method::GET,
        |state: State<Isu>,
         session: Session,
         path: Path<ParamUserName>|
         -> Result<HttpResponse, Error> {
            let login_user = match state.user(session)? {
                None => return Ok(http_redirect("/login", 303)),
                Some(user) => user,
            };

            let (channels, _) = state.get_channel_list_info(None)?;
            let user_name = &path.user_name;
            let user: Option<User> =
                state.first_sql("SELECT * FROM user WHERE name = ?", (user_name,))?;
            match user {
                None => Ok(http_status(404)),
                Some(user) => {
                    let self_profile = user.id == login_user.id;
                    state
                        .render(
                            "profile",
                            &json!({
                                "channels": channels,
                                "user": user,
                                "self_profile": self_profile
                            }),
                        )
                        .map(http_ok)
                }
            }
        },
    );

    app = app.route(
        "/add_channel",
        Method::GET,
        |state: State<Isu>, session: Session| -> Result<HttpResponse, Error> {
            let user = match state.user(session)? {
                None => return Ok(http_redirect("/login", 303)),
                Some(user) => user,
            };

            let (channels, _) = state.get_channel_list_info(None)?;
            state
                .render(
                    "add_channel",
                    &json!({
                        "user": user,
                        "channels": channels
                    }),
                )
                .map(http_ok)
        },
    );

    app = app.route(
        "/add_channel",
        Method::POST,
        |state: State<Isu>,
         session: Session,
         form: Form<ParamChannel>|
         -> Result<HttpResponse, Error> {
            let _user = match state.user(session)? {
                None => return Ok(http_redirect("/login", 303)),
                Some(user) => user,
            };

            let name = &form.name;
            let description = &form.description;
            let channel_id = state.pool.prep_exec("INSERT INTO channel (name, description, updated_at, created_at) VALUES (?, ?, NOW(), NOW())", (name, description))
                 .map_err(err)?
                 .last_insert_id();

            Ok(http_redirect(&format!("/channel/{}", channel_id), 303))
        },
    );

    app = app.route(
        "/profile",
        Method::POST,
        |state: State<Isu>,
         req: HttpRequest<Isu>,
         session: Session|
         -> FutureResponse<HttpResponse> {
            let fut = state.user(session).into_future().and_then(
                move |user| -> Box<Future<Item = HttpResponse, Error = Error>> {
                    let user = match user {
                        None => return Box::new(Ok(http_redirect("/login", 303)).into_future()),
                        Some(user) => user,
                    };

                    let fut = self::multipart::process_multipart(req.multipart()).and_then(
                        move |values| -> Result<HttpResponse, Error> {
                            use self::multipart::FormData;
                            let mut display_name: Option<String> = None;
                            let mut avatar_name: Option<String> = None;
                            let mut avatar_data: Option<Vec<u8>> = None;
                            for value in values {
                                match value {
                                    FormData::Data { name, value } => if &name == "display_name" {
                                        display_name = Some(value);
                                    } else {
                                        continue;
                                    },
                                    FormData::File {
                                        name,
                                        filename,
                                        mut file,
                                    } => if name == "avatar_icon" {
                                        if filename != "" {
                                            use std::path::Path;
                                            let ext = Path::new(&filename)
                                                .extension()
                                                .and_then(OsStr::to_str)
                                                .unwrap_or("");
                                            if !["jpg", "jpeg", "png", "gif"].contains(&ext) {
                                                return Ok(http_status(400));
                                            }

                                            if AVATAR_MAX_SIZE < file.metadata()?.len() {
                                                return Ok(http_status(400));
                                            }
                                            let mut data = vec![];
                                            file.read_to_end(&mut data)?;
                                            let digest = Sha1::digest(&data);
                                            avatar_name = Some(format!("{:x}.{}", digest, ext));
                                            avatar_data = Some(data);
                                        }
                                    } else {
                                        continue;
                                    },
                                }
                            }
                            if let (Some(avatar_name), Some(avatar_data)) =
                                (avatar_name, avatar_data)
                            {
                                state.exec_sql(
                                    "INSERT INTO image (name, data) VALUES (?, ?)",
                                    (&avatar_name, &avatar_data),
                                )?;
                                state.exec_sql(
                                    "UPDATE user SET avatar_icon = ? WHERE id = ?",
                                    (&avatar_name, user.id),
                                )?;
                            }
                            if let Some(display_name) = display_name {
                                state.exec_sql(
                                    "UPDATE user SET display_name = ? WHERE id = ?",
                                    (display_name, user.id),
                                )?;
                            }

                            Ok(http_redirect("/", 303))
                        },
                    );
                    Box::new(fut)
                },
            );
            Box::new(fut)
        },
    );

    app = app.route(
        "/icons/{file_name}",
        Method::GET,
        |state: State<Isu>, path: Path<ParamFilename>| -> Result<HttpResponse, Error> {
            use std::path::Path;
            let file_name = &path.file_name;
            let data: Option<Vec<u8>> =
                state.first_sql("SELECT data FROM image WHERE name = ?", (file_name,))?;
            let ext = Path::new(file_name)
                .extension()
                .and_then(OsStr::to_str)
                .unwrap_or("");
            let mime = ext2mime(ext);
            match (data, mime) {
                (Some(data), Some(mime)) => Ok(HttpResponse::Ok().content_type(mime).body(data)),
                _ => Ok(http_status(404)),
            }
        },
    );

    app
}

pub fn main() {
    env_logger::init();

    let isu = Isu::new();
    server::new(move || app(isu.clone()))
        .bind("127.0.0.1:5000")
        .expect("Can not bind to port 5000")
        .run();
}

mod multipart {
    use super::{err, Error};
    use actix_web::error::PayloadError;
    use actix_web::multipart::Multipart;
    use actix_web::multipart::MultipartItem;
    use bytes::Bytes;
    use futures::prelude::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempfile;

    #[derive(Debug)]
    pub enum FormData {
        Data {
            name: String,
            value: String,
        },
        File {
            name: String,
            filename: String,
            file: File,
        },
    }
    type BoxFut<'a, T, E> = Box<Future<Item = T, Error = E> + 'a>;

    pub fn process_multipart<S>(multipart: Multipart<S>) -> BoxFut<'static, Vec<FormData>, Error>
    where
        S: Stream<Item = Bytes, Error = PayloadError> + 'static,
    {
        let fut = multipart
            .map_err(err)
            .and_then(|item| -> BoxFut<Option<FormData>, Error> {
                match item {
                    MultipartItem::Nested(_) => unimplemented!("not needed for now"),
                    MultipartItem::Field(field) => {
                        debug!("multipart field: {:?}", field);
                        let disposition = match field.content_disposition() {
                            Some(d) => d,
                            None => return Box::new(Ok(None).into_future()),
                        };

                        let name = match disposition.get_name() {
                            Some(n) => n.to_string(),
                            None => return Box::new(Ok(None).into_future()),
                        };
                        let filename = disposition.get_filename();
                        if let Some(filename) = filename {
                            let filename = filename.to_string();
                            let fut = tempfile()
                                .map_err(err)
                                .into_future()
                                .and_then(|tempfile| {
                                    let file = tempfile.try_clone()?;
                                    Ok((tempfile, file))
                                })
                                .and_then(|(mut tempfile, mut file)| {
                                    field
                                        .map_err(err)
                                        .concat2()
                                        .and_then(move |bytes| {
                                            tempfile.write_all(&bytes).map_err(err)
                                        })
                                        .and_then(move |_| {
                                            use std::io::{Seek, SeekFrom};
                                            file.seek(SeekFrom::Start(0)).map_err(err)?;

                                            Ok(Some(FormData::File {
                                                name,
                                                filename,
                                                file,
                                            }))
                                        })
                                });
                            Box::new(fut)
                        } else {
                            let fut = field
                                .map_err(err)
                                .concat2()
                                .and_then(|value| String::from_utf8(value.to_vec()).map_err(err))
                                .and_then(|value| Ok(Some(FormData::Data { name, value })));
                            Box::new(fut)
                        }
                    }
                }
            })
            .filter_map(|id| id)
            .collect();
        Box::new(fut)
    }
}
