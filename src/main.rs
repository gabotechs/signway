use anyhow::anyhow;
use std::error::Error;
use std::str::FromStr;
use tokio::sync::broadcast::error::RecvError;

use async_trait::async_trait;
use clap::Parser;
use tracing::{error, info};

use signway_server::http_body_util::Full;
use signway_server::hyper::header::HeaderName;
use signway_server::hyper::{Response, StatusCode};
use signway_server::{
    BytesTransferredInfo, GetSecretResponse, HeaderMap, SecretGetter, SecretGetterResult,
    SignwayServer,
};

#[derive(Parser, Debug, Clone)]
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
        help = "disables the bytes transferred monitoring. This feature is experimental, because hyper does not put things easy for tracking IO results in the responses, and the current implementation might have some performance implications. https://github.com/hyperium/hyper/issues/2181"
    )]
    no_bytes_monitor: bool,

    #[arg(
        long,
        help = "sets the Access-Control-Allow-Origin that will be answered in each request"
    )]
    access_control_allow_origin: Option<String>,

    #[arg(
        long,
        help = "sets the Access-Control-Allow-Methods that will be answered in each request"
    )]
    access_control_allow_methods: Option<String>,

    #[arg(
        long,
        help = "sets the Access-Control-Allow-Headers that will be answered in each request"
    )]
    access_control_allow_headers: Option<String>,
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
    async fn get_secret(&self, id: &str) -> Result<GetSecretResponse, Box<dyn Error>> {
        if id != self.id {
            return Ok(GetSecretResponse::EarlyResponse(
                Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Full::default())?,
            ));
        }
        Ok(GetSecretResponse::Secret(SecretGetterResult {
            secret: self.secret.clone(),
            headers_extension: self.headers.clone(),
        }))
    }
}

fn log_info(info: BytesTransferredInfo) {
    let bytes = info.bytes;
    let kind = info.kind.to_string();
    let id = info.id;
    info!(bytes, id, kind, "{id} Transferred {bytes} Bytes {kind}");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().init();

    let args: Args = Args::parse();
    let config: Config = args.clone().try_into()?;
    let mut server = SignwayServer::from_env(config);

    if !args.no_bytes_monitor {
        let mut rx = server.subscribe_to_monitoring();
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(info) => {
                        log_info(info);
                    }
                    Err(err) => match err {
                        RecvError::Closed => return,
                        RecvError::Lagged(err) => {
                            error!("Monitoring thread is lagging behind: {err}")
                        }
                    },
                };
            }
        });
    }
    if let Some(value) = args.access_control_allow_headers {
        server = server.access_control_allow_headers(&value)?;
    }
    if let Some(value) = args.access_control_allow_methods {
        server = server.access_control_allow_methods(&value)?;
    }
    if let Some(value) = args.access_control_allow_origin {
        server = server.access_control_allow_origin(&value)?;
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
