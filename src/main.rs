use anyhow::anyhow;
use std::str::FromStr;

use async_trait::async_trait;
use clap::Parser;
use tracing::info;

use signway_server::hyper::body::HttpBody;
use signway_server::hyper::header::HeaderName;
use signway_server::hyper::{Body, Request, Response, StatusCode};
use signway_server::{
    CallbackResult, GetSecretResponse, HeaderMap, OnRequest, OnSuccess, SecretGetter,
    SecretGetterResult, SignwayServer,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(help = "access id that is expected to sign urls for this server")]
    id: String,

    #[arg(help = "secret associated to the access id")]
    secret: String,

    #[arg(
        long,
        help = "if a signed url is authentic, this headers will be added to the proxy-ed request"
    )]
    header: Vec<String>,
}

struct Config {
    id: String,
    secret: String,
    headers: HeaderMap,
}

impl TryInto<Config> for Args {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Config, Self::Error> {
        let mut headers = HeaderMap::new();

        for h in self.header {
            let mut split = h.splitn(2, ':');
            let k = split
                .next()
                .ok_or_else(|| anyhow!("Invalid header '{h}'"))?;
            let v = split
                .next()
                .ok_or_else(|| anyhow!("Invalid header '{h}'"))?
                .to_string();
            headers.insert(HeaderName::from_str(k)?, v.trim().parse()?);
        }

        Ok(Config {
            id: self.id,
            secret: self.secret,
            headers,
        })
    }
}

#[async_trait]
impl SecretGetter for Config {
    type Error = anyhow::Error;

    async fn get_secret(&self, id: &str) -> Result<GetSecretResponse, Self::Error> {
        if id != self.id {
            return Ok(GetSecretResponse::EarlyResponse(
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::empty())?,
            ));
        }
        Ok(GetSecretResponse::Secret(SecretGetterResult {
            secret: self.secret.clone(),
            headers_extension: self.headers.clone(),
        }))
    }
}

struct CallbackLogger;

#[async_trait]
impl OnRequest for CallbackLogger {
    async fn call(&self, id: &str, req: &Request<Body>) -> CallbackResult {
        let size = req.size_hint().exact().unwrap_or(req.size_hint().lower());
        info!(
            size = size,
            id = id,
            "Received a request with size {size} Bytes from id {id}"
        );
        CallbackResult::Empty
    }
}

#[async_trait]
impl OnSuccess for CallbackLogger {
    async fn call(&self, id: &str, res: &Response<Body>) -> CallbackResult {
        let size = res.size_hint().exact().unwrap_or(res.size_hint().lower());
        info!(
            size = size,
            id = id,
            "Received a proxy-ed response with size {size} Bytes from id {id}"
        );
        CallbackResult::Empty
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Args = Args::parse();
    let config: Config = args.try_into()?;
    tracing_subscriber::fmt().json().init();
    let server = SignwayServer::from_env(config)
        .on_request(CallbackLogger {})
        .on_success(CallbackLogger {});

    tokio::select! {
        result = server.start() => {
            result
        }
        _ = tokio::signal::ctrl_c() => {
            Ok(())
        }
    }
}
