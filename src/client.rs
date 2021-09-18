use std::collections::HashSet;
use std::time::Duration;
use std::convert::TryFrom;
use std::path::PathBuf;

use jsonwebtoken as jwt;
use quick_from::QuickFrom;
use serde::Deserialize;
use hyperlocal::{UnixClientExt, Uri};

use crate::crypto;
use crate::{PostLoginRequest, PostLoginResponse, GetUserResponse};


type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, QuickFrom)]
pub enum Error {
    AlgorithmNotAllowed(jwt::Algorithm),
    VersionMismatch,

    /// Error from the api response
    Api(String),

    #[quick_from]
    Jwt(jwt::errors::Error),

    #[quick_from]
    Hyper(hyper::Error),

    #[quick_from]
    SerdeJson(serde_json::Error),

    #[quick_from]
    Http(http::Error),

    #[quick_from]
    Io(std::io::Error),
}


fn parse_error(body : &[u8]) -> Error {

    #[derive(Deserialize)]
    struct E {
        error : String
    }

    match serde_json::from_slice::<E>(body) {
        Ok(e) => Error::Api(e.error),
        Err(e) => e.into(),
    }
}

#[derive(Deserialize)]
pub struct Config {
    pub server_path : String,
    pub server_name : String,
    pub client_name : String,
    pub alg : jwt::Algorithm,
    pub pub_key_file : String,
}

impl TryFrom<Config> for Client {
    type Error = Error;

    fn try_from(
        config : Config,
    ) -> Result<Self> {
        use jwt::Algorithm::*;

        let pub_key_str = std::fs::read_to_string(config.pub_key_file)?;

        let pub_key = match config.alg {
            ES256 | ES384 => jwt::DecodingKey::from_ec_pem(pub_key_str.as_bytes())?,
            RS256 | RS384 | RS512 |
            PS256 | PS384 | PS512 => jwt::DecodingKey::from_rsa_pem(pub_key_str.as_bytes())?,
            alg => return Err(Error::AlgorithmNotAllowed(alg))
        }.into_static();

        let validation = make_validation(
            config.alg,
            config.client_name.clone(),
            config.server_name,
        );

        Ok(Client{
            pub_key,
            validation,
            path : config.server_path.into(),
            client_name : config.client_name,
            client : hyper::Client::unix(),
        })
    }
}

fn make_validation(
    alg : jwt::Algorithm,
    aud : String,
    iss : String,
) -> jwt::Validation {
    let mut aud_set = HashSet::new();
    aud_set.insert(aud.to_string());

    jwt::Validation{
        validate_exp : true,
        iss : Some(iss.to_string()),
        aud : Some(aud_set),
        algorithms : vec![alg],
        ..Default::default()
    }
}

pub struct Client {
    path : PathBuf,
    client_name : String,
    client : hyper::Client<hyperlocal::UnixConnector>,
    pub_key : jwt::DecodingKey<'static>,
    validation : jwt::Validation,
}

impl Client {
    /// gets a token form the credentials
    pub async fn login(
        &self,
        name : &str,
        pass : &str,
        duration : Duration
    ) -> Result<String> {

        let req = http::Request::builder()
            .uri(Uri::new(&self.path, "/login"))
            .method("POST")
            .body(serde_json::to_string(&PostLoginRequest{
                name : name.to_string(),
                pass : pass.to_string(),
                aud : self.client_name.clone(),
                duration : duration.as_secs()
            }).unwrap().into())?;

        let (parts, body) = self.client.request(req).await?.into_parts();
        let body = hyper::body::to_bytes(body).await?;

        if parts.status != http::status::StatusCode::OK {
            return Err(parse_error(&body))
        }

        Ok(serde_json::from_slice::<PostLoginResponse>(&body)?.token)
    }


    /// verifies the validity of the token and returns the user name
    pub async fn validate_token(&self, token : &str) -> Result<String> {
        let token = crypto::Token::validate(
            token,
            &self.validation,
            &self.pub_key
        )?;

        let req = http::Request::builder()
            .uri(Uri::new(&self.path, &format!("/user/{}", token.sub)))
            .method("GET")
            .body("".into())?;

        let (parts, body) = self.client.request(req).await?.into_parts();
        let body = hyper::body::to_bytes(body).await?;
        if parts.status != http::status::StatusCode::OK {
            return Err(parse_error(&body))
        }


        let token_version = serde_json::from_slice::<GetUserResponse>(&body)?.token_version;
        if token_version != token.version {
            return Err(Error::VersionMismatch)
        }

        Ok(token.sub)
    }
}
