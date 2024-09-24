use crate::api::CacheConn;
use crate::token::{Claims, SECRET_KEY};
use crate::verify_password;
use crate::LoginInput;
use chrono::{Duration, Utc};
use diesel::prelude::*;
use diesel::result::Error as DieselError;
use jsonwebtoken::{encode, EncodingKey, Header};
use rocket::http::Status;
use rocket::response::status;
use rocket::serde::json::Json;
use rocket::serde::Serialize;
use rocket_db_pools::deadpool_redis::redis::AsyncCommands;
use rocket_db_pools::diesel::{AsyncPgConnection, RunQueryDsl};
use rocket_db_pools::Connection;

use crate::models::*;
use crate::schema::*;

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
}
pub struct UserRepo;

impl UserRepo {
    pub async fn create(c: &mut AsyncPgConnection, new_user: NewUser) -> QueryResult<User> {
        diesel::insert_into(users::table)
            .values(new_user)
            .get_result(c)
            .await
    }

    // pub async fn find(c: &mut AsyncPgConnection, id: i32) -> QueryResult<User> {
    //     users::table.find(id).get_result(c).await
    // }

    pub async fn login(
        c: &mut AsyncPgConnection,
        login: Json<LoginInput>,
        mut cache: Connection<CacheConn>,
    ) -> Result<Json<TokenResponse>, status::Custom<&'static str>> {
        // Find the user in the database
        match users::table
            .filter(users::username.eq(&login.username))
            .get_result::<User>(c)
            .await
        {
            Ok(user) => {
                if verify_password(&user.password_hash, &login.password) {
                    // Generate JWT token
                    let expiration = Utc::now()
                        .checked_add_signed(Duration::seconds(300)) // Example: 5 minutes expiry
                        .expect("valid timestamp")
                        .timestamp() as usize;

                    let claims = Claims {
                        sub: user.id.to_string(),
                        exp: expiration,
                    };

                    let token = encode(
                        &Header::default(),
                        &claims,
                        &EncodingKey::from_secret(&SECRET_KEY),
                    )
                    .map_err(|_| {
                        status::Custom(
                            rocket::http::Status::InternalServerError,
                            "Token creation error",
                        )
                    })?;

                    // Store the token in Redis with an expiration
                    let redis_key = format!("user_token:{}", user.id);

                    // Make sure to use the correct method to set the value in Redis
                    match cache
                        .set_ex::<String, String, u64>(redis_key, token.clone(), 60)
                        .await
                    {
                        Ok(_) => Ok(Json(TokenResponse { token })),
                        Err(_) => Err(status::Custom(Status::InternalServerError, "Redis error")),
                    }
                } else {
                    Err(status::Custom(
                        rocket::http::Status::Unauthorized,
                        "Invalid username or password",
                    ))
                }
            }
            Err(DieselError::NotFound) => Err(status::Custom(
                rocket::http::Status::NotFound,
                "User not found",
            )),
            Err(_) => Err(status::Custom(
                rocket::http::Status::InternalServerError,
                "Database error",
            )),
        }
    }
}
