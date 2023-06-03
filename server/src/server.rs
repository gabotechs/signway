use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::u16;

use crate::gateway_middleware::GatewayMiddleware;
use anyhow::Result;
use hyper::service::service_fn;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::secret_getter::SecretGetter;

pub struct SignwayServer<T: SecretGetter + 'static> {
    pub port: u16,
    pub secret_getter: T,
    pub gateway_middleware: Box<dyn GatewayMiddleware>,
}

struct NoneGatewayMiddleware;

impl GatewayMiddleware for NoneGatewayMiddleware {}

impl<T: SecretGetter> SignwayServer<T> {
    pub fn from_env(secret_getter: T) -> Result<SignwayServer<T>> {
        Ok(SignwayServer {
            port: u16::from_str(&std::env::var("PORT").unwrap_or("3000".to_string()))
                .expect("failed to parse PORT env variable"),
            secret_getter,
            gateway_middleware: Box::new(NoneGatewayMiddleware {}),
        })
    }

    pub fn with_middleware(mut self, gateway_middleware: impl GatewayMiddleware + 'static) -> Self {
        self.gateway_middleware = Box::new(gateway_middleware);
        self
    }

    pub async fn start(self) -> Result<()> {
        let in_addr: SocketAddr = ([0, 0, 0, 0], self.port).into();

        let arc_self = Arc::new(self);
        let listener = TcpListener::bind(in_addr).await?;

        info!("Server running in {}", in_addr);
        loop {
            let (stream, _) = listener.accept().await?;

            let arc_self = arc_self.clone();

            let service = service_fn(move |req| {
                let arc_self = arc_self.clone();
                async move { arc_self.route_gateway(req).await }
            });

            tokio::spawn(async move {
                if let Err(err) = hyper::server::conn::Http::new()
                    .serve_connection(stream, service)
                    .await
                {
                    error!("Failed to serve the connection: {:?}", err);
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hyper::StatusCode;
    use reqwest::header::HeaderMap;
    use time::{OffsetDateTime, PrimitiveDateTime};
    use url::Url;

    use crate::_test_tools::tests::{DummyGatewayMiddleware, InMemorySecretGetter};
    use crate::secret_getter::SecretGetterResult;
    use crate::signing::{SignRequest, UrlSigner};

    use super::*;

    fn server_for_testing<const N: usize>(
        config: [(&str, &str); N],
    ) -> SignwayServer<InMemorySecretGetter> {
        SignwayServer {
            port: 3000,
            gateway_middleware: Box::new(DummyGatewayMiddleware {}),
            secret_getter: InMemorySecretGetter(HashMap::from(config.map(|e| {
                (
                    e.0.to_string(),
                    SecretGetterResult {
                        secret: e.1.to_string(),
                        headers_extension: HeaderMap::new(),
                    },
                )
            }))),
        }
    }

    fn base_request() -> SignRequest {
        let now = OffsetDateTime::now_utc();

        SignRequest {
            proxy_url: Url::parse("https://postman-echo.com/get").unwrap(),
            expiry: 10,
            datetime: PrimitiveDateTime::new(now.date(), now.time()),
            method: "GET".to_string(),
            headers: None,
            body: None,
        }
    }

    #[ignore] // something weird happens with the `cargo test` runtime and task spawning
    #[tokio::test]
    async fn simple_get_works() {
        let server = server_for_testing([("foo", "foo-secret")]);
        tokio::task::spawn(server.start());
        let host = "http://localhost:3000";
        let signer = UrlSigner::new("foo", "foo-secret");
        let signed_url = signer.get_signed_url(host, &base_request()).unwrap();

        let response = reqwest::Client::new()
            .get(signed_url)
            .header("host", "localhost:3000")
            .send()
            .await
            .unwrap();

        let status = response.status();
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn signed_with_different_secret_does_not_work() {
        let server = server_for_testing([("foo", "foo-secret")]);
        tokio::task::spawn(server.start());
        let host = "http://localhost:3000";
        let bad_signer = UrlSigner::new("foo", "bad-secret");

        let signed_url = bad_signer.get_signed_url(host, &base_request()).unwrap();

        let response = reqwest::Client::new()
            .get(signed_url)
            .header("host", "localhost:3000")
            .send()
            .await
            .unwrap();

        let status = response.status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
