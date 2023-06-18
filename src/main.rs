use anyhow::anyhow;
use std::str::FromStr;

use async_trait::async_trait;
use clap::Parser;
use tracing::info;

use signway_server::hyper::header::HeaderName;
use signway_server::hyper::{Body, Response, StatusCode};
use signway_server::{
    BytesTransferredKind, GetSecretResponse, HeaderMap, OnBytesTransferred, SecretGetter,
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

    #[arg(
        long,
        help = "disables the bytes transferred monitoring. This feature is experimental, because hyper does not put things easy to track IO results in the responses, and the current implementation might have some performance implications."
    )]
    no_bytes_monitor: bool,
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

struct BytesTransferredLogger;

#[async_trait]
impl OnBytesTransferred for BytesTransferredLogger {
    async fn call(&self, id: &str, bytes: usize, kind: BytesTransferredKind) {
        let kind = kind.to_string();
        info!(bytes, id, kind, "{id} Transferred {bytes} Bytes {kind}");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Args = Args::parse();
    let disable_monitoring = args.no_bytes_monitor;
    let config: Config = args.try_into()?;
    tracing_subscriber::fmt().json().init();
    let mut server = SignwayServer::from_env(config);
    if !disable_monitoring {
        server = server.on_bytes_transferred(BytesTransferredLogger {});
    }

    tokio::select! {
        result = server.start() => {
            result
        }
        _ = tokio::signal::ctrl_c() => {
            Ok(())
        }
    }
}
