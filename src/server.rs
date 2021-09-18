use std::sync::Arc;
use std::path::PathBuf;

use serde::{Serialize,Deserialize};
use plumb::{Pipe,PipeExt};
use quick_from::QuickFrom;
use hyper::Body;
use hyper::body::Buf;
use http_mux::{route,mux};
use jsonwebtoken as jwt;

use crate::database::Database;
use crate::crypto;
use crate::{PostLoginRequest, PostLoginResponse};

const MAX_DURATION : u64 = 60 * 60 * 24 * 30;

type Result<T> = std::result::Result<T, Error>;
type Request = http::Request<Body>;
type Response = http::Response<Body>;
type Mux = mux::Mux<Error, (), Body, Response>;

#[derive(QuickFrom,Debug)]
pub enum Error {
    DuplicateName(String),
    UserNotFound(String),
    TokenDurationTooBig,
    BadRequest,
    AlgorithmNotAllowed(jwt::Algorithm),
    LoginFailed,

    MustUseHttps,

    #[quick_from]
    Token(crypto::TokenError),

    #[quick_from]
    Jwt(jwt::errors::Error),

    #[quick_from]
    Io(std::io::Error),

    #[quick_from]
    Rusqlite(rusqlite::Error),

    #[quick_from]
    Mux(mux::MuxError),

    #[quick_from]
    SerdeJson(serde_json::Error),

    #[quick_from]
    Argon2(argon2::Error),

    #[quick_from]
    Hyper(hyper::Error),
}


#[derive(Deserialize)]
pub struct Config {
    pub server_name : String,
    pub server_path : String,
    pub alg : jwt::Algorithm,
    pub priv_key_file : String,
    pub pub_key_file : String,
    pub database : String,
}

pub struct Server {
    server_name : String,
    alg : jwt::Algorithm,
    priv_key : jwt::EncodingKey,
    pub_key : String,
    database : Database,
}

    pub fn new_server(config : Config) -> std::result::Result<(Server, PathBuf), Error> {
        let priv_key_string = std::fs::read_to_string(config.priv_key_file)?;

        use jwt::Algorithm::*;
        let priv_key = match config.alg {
            ES256 | ES384 => jwt::EncodingKey::from_ec_pem(priv_key_string.as_bytes())?,
            RS256 | RS384 | RS512 |
            PS256 | PS384 | PS512 => jwt::EncodingKey::from_rsa_pem(priv_key_string.as_bytes())?,
            alg => return Err(Error::AlgorithmNotAllowed(alg))
        };

        let pub_key = std::fs::read_to_string(config.pub_key_file)?;

        let server = Server{
            server_name : config.server_name,
            database : Database::new(&config.database)?,
            alg : config.alg,
            priv_key,
            pub_key,
        };

        Ok((server, config.server_path.into()))
    }

pub fn routes(server : Server) -> impl Pipe<Input = (Request,), Output = Response> {

    macro_rules! register_routes {
        ($($route:ident,)*) => {
            {
                let server = Arc::new(server);
                let mux = http_mux::mux::new_mux::<Error, _, _>();

                $(let mux = $route(Arc::clone(&server), mux);)*

                mux
            }
        }
    }

    let mux = register_routes!{
        post_login,
        get_user,
        get_pub_key,
    }
    .tuple()
    .seq(|res : Result<Response>| {
        match res {
            Ok(res) => res,
            Err(err)  => render_error(err),
        }
    });


    log_middleware(mux)
}

fn post_login(server : Arc<Server>, m : Mux) -> Mux {
    m.handle(
        route!(POST / "login"),
        mux::new_handler()
        .map_bind(server.clone())
        .aand_then(|req : Request, server : Arc<Server>| async move {
            let reader = hyper::body::aggregate(req.into_body()).await?.reader();
            let req : PostLoginRequest = serde_json::from_reader(reader)
                .map_err(|_| Error::BadRequest)?;

            let user = server.database.get_user_by_name(&req.name).await?;

            if !crypto::verify_password(&user.pass_hash, req.pass.as_bytes())? {
                return Err(Error::LoginFailed)
            }

            let token = crypto::Token{
                iss : server.server_name.to_string(),
                aud : req.aud,
                sub : req.name,
                version : user.token_version,
            }.issue(
                &server.priv_key,
                server.alg,
                std::time::Duration::from_secs(req.duration.min(MAX_DURATION)),
            )?;

            let s = serde_json::to_string(&PostLoginResponse{ token })?;
            Ok(Response::new(s.into()))
        })
    )

}

fn get_user(server : Arc<Server>, m : Mux) -> Mux {
    #[derive(Serialize)]
    struct Res {
        name : String,
        token_version : u32,
    }

    m.handle(
        route!(GET / "user" / String),
        mux::new_handler()
        .map_bind(server.clone())
        .aand_then(|_, user : String, server : Arc<Server>| async move {
            let user = server.database.get_user_by_name(&user).await?;
            let s = serde_json::to_string(&Res{
                name : user.name,
                token_version : user.token_version,
            })?;

            Ok(Response::new(s.into()))
        })
    )
}

fn get_pub_key(server : Arc<Server>, m : Mux) -> Mux {
    m.handle(
        route!(GET / "pub-key"),
        mux::new_handler()
        .map_bind(server.clone())
        .map(|_, server : Arc<Server>| {
            Response::new(server.pub_key.clone().into())
        })
    )
}

fn render_error(err : Error) -> Response {
    use http::StatusCode as S;
    use Error::*;

    eprintln!("{:?}", &err);

    let status;
    let body;

    match err {
        UserNotFound(_) => {
            status = S::NOT_FOUND;
            body   = "user not found";
        },
        BadRequest => {
            status = S::BAD_REQUEST;
            body = "bad request";
        },
        LoginFailed => {
            status = S::UNAUTHORIZED;
            body = "login failed";
        },
        Mux(mux::MuxError::NotFound(_)) => {
            status = S::NOT_FOUND;
            body = "route not found";
        },
        Mux(mux::MuxError::MethodNotAllowed(_, _)) => {
            status = S::METHOD_NOT_ALLOWED;
            body = "method not defined for route";
        },
        Mux(mux::MuxError::Parse(_, _)) => {
            status = S::BAD_REQUEST;
            body = "invalid path values";
        },
        _ => {
            status = S::INTERNAL_SERVER_ERROR;
            body   = "internal server error";
        }
    }

    let body = format!("{{ \"error\": \"{}\" }}", body);

   http::response::Builder::new()
       .status(status)
       .body(body.into())
       .unwrap()
}

fn log_middleware<P>(next : P) -> impl Pipe<Input = (Request,), Output = P::Output>
where
    P : Pipe<Input = (Request,), Output = Response> + Send + Sync + 'static,
{
    // TODO: probably not ideal?
    // bettern than cloning the whole mux
    let next = Arc::new(next);

    plumb::id()
    .aseq(|req : Request| async move {
        let pre_details = format!(
            "{} {}",
            req.method(),
            req.uri().path(),
        );

        let start = tokio::time::Instant::now();

        let res = next.run((req,)).await;

        let end = tokio::time::Instant::now();
        let delta = end - start;

        println!(
            "{} {} {:?}",
            res.status(),
            pre_details,
            delta
        );

        res
    })
}

