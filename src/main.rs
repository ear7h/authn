use std::convert::Infallible;

use plumb::{Pipe,PipeExt};
use authn::server::Config;
use hyperlocal::UnixServerExt;
use hyper::service::{make_service_fn, service_fn};
use hyper::Server;


#[tokio::main]
async fn main() {
    println!("starting server");

    let args = std::env::args().collect::<Vec<_>>();
    let config_file = match &args[..] {
        [_, config] => config,
        _ => {
            eprintln!("usage: ./authn config.json");
            std::process::exit(1);
        }
    };

    let config_string = std::fs::read_to_string(&config_file).unwrap();
    let config : Config = serde_json::from_str(&config_string).unwrap();
    let (server, path) = authn::server::new_server(config).unwrap();
    let server = authn::server::routes(server);

    if path.exists() {
        std::fs::remove_file(&path).unwrap();
    }

    let pipe : &'static _= Box::leak(Box::new(
        server.tuple().seq(|res| Ok::<_, Infallible>(res))
    ));

    let make_service = make_service_fn(move |_| async move {
        Ok::<_, Infallible>(service_fn(move |req| {
            pipe.run((req,))
        }))
    });

    Server::bind_unix(path).unwrap().serve(make_service).await.unwrap();

}
