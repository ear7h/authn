use serde::{Serialize,Deserialize};

pub mod models;

#[cfg(feature = "server")]
pub mod database;

#[cfg(feature = "server")]
pub mod server;

pub mod crypto;
pub mod client;



#[derive(Serialize,Deserialize)]
pub struct PostLoginRequest {
    pub aud : String,
    pub duration : u64,
    pub name : String,
    pub pass : String,
}

#[derive(Serialize,Deserialize)]
pub struct PostLoginResponse {
    pub token : String,
}

#[derive(Serialize,Deserialize)]
pub struct GetUserResponse {
    name : String,
    token_version : u32,
}

