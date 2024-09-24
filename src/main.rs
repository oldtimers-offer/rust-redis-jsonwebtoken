mod api;
mod auth;
mod models;
mod repo;
mod schema;
mod token;

use crate::repo::TokenResponse;
use crate::token::AuthenticatedUser;
use api::{server_error, CacheConn, DbConn};
use auth::{hash_password, verify_password};
use models::NewUser;
use repo::UserRepo;
use rocket::http::Status;
use rocket::response::status;
use rocket::response::status::Custom;
use rocket::serde::json::Json;
use rocket::serde::json::{json, Value};
use rocket::serde::Deserialize;
use rocket::{get, launch, post, routes};
use rocket::{Build, Rocket};
use rocket_db_pools::Connection;
use rocket_db_pools::Database;

#[derive(Deserialize)]
struct RegisterInput {
    username: String,
    password: String,
}

#[post("/register", data = "<user>")]
async fn register(
    user: Json<RegisterInput>,
    mut conn: Connection<DbConn>,
) -> Result<Custom<Value>, Custom<Value>> {
    let hashed_password = hash_password(&user.password);
    let new_user = NewUser {
        username: user.username.clone(),
        password_hash: hashed_password,
    };

    UserRepo::create(&mut conn, new_user.into())
        .await
        .map(|user| Custom(Status::Created, json!(user)))
        .map_err(|e| server_error(e.into()))
}

#[derive(Deserialize)]
pub struct LoginInput {
    pub username: String,
    pub password: String,
}

#[post("/login", data = "<login>")]
async fn login(
    mut conn: Connection<DbConn>,
    login: Json<LoginInput>,
    cash: Connection<CacheConn>,
) -> Result<Json<TokenResponse>, status::Custom<&'static str>> {
    UserRepo::login(&mut conn, login, cash).await
}

#[get("/protected")]
pub fn protected_route(_user: AuthenticatedUser) -> &'static str {
    "This is a protected route!"
}

#[launch]
fn rocket() -> Rocket<Build> {
    rocket::build()
        .mount("/", routes![register, login, protected_route])
        .attach(DbConn::init())
        .attach(CacheConn::init())
}
