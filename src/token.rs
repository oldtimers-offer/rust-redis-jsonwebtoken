use crate::api::CacheConn;
use dotenv::dotenv;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use once_cell::sync::Lazy;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket_db_pools::deadpool_redis::redis::AsyncCommands;
use rocket_db_pools::Connection;
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // The subject (user identifier)
    pub exp: usize,  // Expiry time
}

pub static SECRET_KEY: Lazy<Vec<u8>> = Lazy::new(|| {
    dotenv().ok(); // Load .env file
    let key = env::var("SECRET_KEY").expect("SECRET_KEY must be set");
    key.into_bytes() // Convert String to Vec<u8>
});

pub struct AuthenticatedUser {
    pub user_id: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = Status;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        // Get the token from the Authorization header
        let token = match request
            .headers()
            .get_one("Authorization")
            .and_then(|header| header.strip_prefix("Bearer "))
        {
            Some(token) => token,
            None => return Outcome::Forward(Status::Unauthorized),
        };

        // Decode the token to extract the user ID
        let claims = match decode::<Claims>(
            token,
            &DecodingKey::from_secret(&SECRET_KEY),
            &Validation::new(Algorithm::HS256),
        ) {
            Ok(token_data) => token_data.claims,
            Err(_) => return Outcome::Forward(Status::Unauthorized),
        };

        let user_id = claims.sub; // Extract the user ID from claims

        // Get Redis connection
        let mut redis_conn = request
            .guard::<Connection<CacheConn>>()
            .await
            .expect("Can not connect to Redis in request guard");

        // Check if token exists in Redis
        let redis_key = format!("user_token:{}", user_id);
        match redis_conn.as_mut().exists(redis_key).await {
            Ok(true) => {
                // Token is valid and exists in Redis, proceed to decode
                match decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(&SECRET_KEY),
                    &Validation::new(Algorithm::HS256),
                ) {
                    Ok(token_data) => {
                        let claims = token_data.claims;
                        Outcome::Success(AuthenticatedUser {
                            user_id: claims.sub,
                        })
                    }
                    Err(_) => Outcome::Forward(Status::Unauthorized),
                }
            }
            Ok(false) => Outcome::Forward(Status::Unauthorized), // Token doesn't exist
            Err(_) => Outcome::Forward(Status::InternalServerError), // Redis error
        }
    }
}
