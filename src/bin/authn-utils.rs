use std::time::Duration;
use std::str::FromStr;
use std::convert::TryInto;


use authn::database::Database;
use authn::crypto;
use authn::client::{Config, Client};


#[tokio::main]
async fn main() {

    let config_file = std::env::var("AUTHN_CONFIG").unwrap_or("config.json".to_string());

    let config_string = if let Ok(s) = std::fs::read_to_string(&config_file) {
        s
    } else {
        eprintln!(concat!(
            "could not find config file, set AUTHN_CONFIG ",
            "or write a file to config.json"
        ));
        std::process::exit(1);
    };

    let config : Config = serde_json::from_str(&config_string).unwrap();
    let client : Client = config.try_into().unwrap();

    let args = std::env::args().collect::<Vec<_>>();
    let args_ref = args.iter().map(|s| s.as_str()).collect::<Vec<_>>();

    match &args_ref[1..] {
        ["help", "add-user"] => {
            usage("add-user db_file user");
        },
        ["add-user", db_file, user] => {
            let db = Database::new(db_file).unwrap();
            let pass = rpassword::prompt_password_stdout("password: ").unwrap();
            dbg!(&pass);
            let pass_hash = crypto::encode_password(pass.as_bytes()).unwrap();

            db.insert_user(&user, &pass_hash).await.unwrap();
        },
        ["help", "update-user-pass"] => {
            usage("update-user-pass db_file user");
        },
        ["update-user-pass", db_file, user] => {
            let db = Database::new(db_file).unwrap();
            let pass = rpassword::prompt_password_stdout("password: ").unwrap();
            let pass_hash = crypto::encode_password(pass.as_bytes()).unwrap();

            db.insert_user(&user, &pass_hash).await.unwrap();
        },
        ["help", "invalidate-user-tokens"] => {
            usage("invalidate-user-tokens db_file user");
        },
        ["invalidate-user-tokens", db_file, user] => {
            let db = Database::new(db_file).unwrap();

            db.increment_token(&user).await.unwrap();
        },
        ["help", "validate-token"] => {
            usage("validate-token token");
        },
        ["validate-token", token] => {
            let user_name = client.validate_token(token).await.unwrap();
            println!("{}", user_name);
        },
        ["help", "login"] => {
            usage("login user duration");
        },
        ["login", user, duration] => {
            let secs = u64::from_str(&duration).unwrap();

            let pass = rpassword::prompt_password_stdout("password: ").unwrap();

            let token = client.login(
                user,
                &pass,
                Duration::from_secs(secs)
            ).await.unwrap();

            println!("{}", token);
        },
        args => {
            eprintln!("invalid args: {:?}", args);
            eprintln!("try `./authn-utils help cmd` where cmd is:");

            let cmds = &[
                "add-user",
                "update-user-pass",
                "invalidate-user-tokens",
                "validate-token",
                "login",
            ];

            for cmd in cmds.iter() {
                eprintln!("{}", cmd);
            }

            std::process::exit(1);
        }
    }
}

fn usage(s : &str) -> ! {
    println!("usage: ./authn-utils {}", s);
    std::process::exit(0)
}
