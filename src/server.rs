use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::u16;

use anyhow::Result;
use hyper::service::service_fn;
use tokio::net::TcpListener;
use url::Url;

use crate::secret_getter::{InMemorySecretGetter, SecretGetter};

pub struct Server<T: SecretGetter> {
    pub port: u16,
    pub self_host: Url,
    pub secret_getter: T,
}

impl<T: SecretGetter> Server<T> {
    pub fn from_env(secret_getter: T) -> Result<Server<T>> {
        Ok(Server {
            port: u16::from_str(&std::env::var("PORT").unwrap_or("3000".to_string()))
                .expect("failed to parse PORT env variable"),
            self_host: Url::parse(
                &std::env::var("SELF_HOST").unwrap_or("http://localhost".to_string()),
            )
            .expect("failed to parse SELF_HOST env variable"),
            secret_getter,
        })
    }

    pub fn for_testing<const N: usize>(config: [(&str, &str); N]) -> Server<InMemorySecretGetter> {
        Server {
            port: 3000,
            self_host: Url::parse("http://localhost:3000").unwrap(),
            secret_getter: InMemorySecretGetter(HashMap::from(
                config.map(|e| (e.0.to_string(), e.1.to_string())),
            )),
        }
    }

    pub async fn start(&'static self) -> Result<()> {
        let in_addr: SocketAddr = ([0, 0, 0, 0], self.port).into();
        let listener = TcpListener::bind(in_addr).await?;

        println!("Server running in {}", in_addr);
        loop {
            let (stream, _) = listener.accept().await?;
            let service = service_fn(|req| self.route_gateway(req));

            tokio::spawn(async move {
                if let Err(err) = hyper::server::conn::Http::new()
                    .serve_connection(stream, service)
                    .await
                {
                    println!("Failed to serve the connection: {:?}", err);
                }
            });
        }
    }
}
