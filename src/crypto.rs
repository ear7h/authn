use std::convert::TryInto;
use std::time::{self,SystemTimeError};

use jsonwebtoken as jwt;
use rand::{thread_rng, Rng};
use serde::{Serialize,Deserialize};
use quick_from::QuickFrom;

pub fn encode_password(pass : &[u8]) -> std::result::Result<String, argon2::Error> {
    let mut salt = [0u8;32];

    tokio::task::block_in_place(|| {
        thread_rng().fill(&mut salt);
    });
    Ok(argon2::hash_encoded(pass, &salt, &Default::default())?)
}

pub fn verify_password(encoded : &str, pass : &[u8]) -> Result<bool, argon2::Error> {
    Ok(argon2::verify_encoded(encoded, pass)?)
}

#[derive(Debug, QuickFrom)]
pub enum TokenError {
    InvalidDuration(Option<SystemTimeError>),
    #[quick_from]
    Jwt(jwt::errors::Error),
}

pub struct Token {
    pub iss : String,
    pub aud : String,
    pub sub : String,
    pub version : u32,
}

impl Token {
    pub fn issue(
        &self,
        enc_key : &jwt::EncodingKey,
        alg : jwt::Algorithm,
        exp_duration : time::Duration,
    ) -> Result<String, TokenError> {
        let now = time::SystemTime::now();
        let iat = now
            .duration_since(time::UNIX_EPOCH)
            .map_err(|err| {
                TokenError::InvalidDuration(Some(err))
            })?
            .as_secs()
            .try_into()
            .unwrap();

        let exp = now
            .checked_add(exp_duration)
            .ok_or(TokenError::InvalidDuration(None))?
            .duration_since(time::UNIX_EPOCH)
            .map_err(|err| {
                TokenError::InvalidDuration(Some(err))
            })?
            .as_secs()
            .try_into()
            .unwrap();

                #[derive(Serialize)]
        pub struct TokenFull<'a> {
            iss :     &'a str,
            aud :     &'a str,
            sub :     &'a str,
            version : u32,
            iat :     u64,
            exp :     u64,
        }

        let tok = TokenFull {
            iss : &self.iss,
            aud : &self.aud,
            sub : &self.sub,
            version : self.version,
            iat,
            exp,
        };

        Ok(jwt::encode(
            &jwt::Header{
                alg : alg,
                ..Default::default()
            },
            &tok,
            &enc_key,
        )?)
    }

    pub fn validate(
        token : &str,
        validation : &jwt::Validation,
        pub_key : &jwt::DecodingKey<'_>,
    ) -> Result<Self, jwt::errors::Error> {

        #[derive(Deserialize)]
        #[allow(dead_code)]
        pub struct TokenFull {
            iss :     String,
            aud :     String,
            sub :     String,
            version : u32,
            iat :     u64,
            exp :     u64,
        }

        let tok : TokenFull = jwt::decode(
            token,
            pub_key,
            validation,
        )
        .map_err(|err| err.into_kind())?
        .claims;

        Ok(Self {
            iss :     tok.iss,
            aud :     tok.aud,
            sub :     tok.sub,
            version : tok.version,
        })
    }
}
