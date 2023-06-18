use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::u16;

use anyhow::Result;
use async_trait::async_trait;
use hyper::client::HttpConnector;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response};
use hyper_tls::HttpsConnector;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::gateway_callbacks::{CallbackResult, OnRequest, OnSuccess};
use crate::secret_getter::SecretGetter;

pub struct SignwayServer<T: SecretGetter + 'static> {
    pub port: u16,
    pub secret_getter: T,
    pub on_request: Box<dyn OnRequest>,
    pub on_success: Box<dyn OnSuccess>,
    pub(crate) client: hyper::Client<HttpsConnector<HttpConnector>, Body>,
}

pub(crate) struct NoneOnRequest;
pub(crate) struct NoneOnSuccess;

#[async_trait]
impl OnRequest for NoneOnRequest {
    async fn call(&self, _req: &Request<Body>) -> CallbackResult {
        CallbackResult::Empty
    }
}

#[async_trait]
impl OnSuccess for NoneOnSuccess {
    async fn call(&self, _res: &Response<Body>) -> CallbackResult {
        CallbackResult::Empty
    }
}

impl<T: SecretGetter> SignwayServer<T> {
    pub fn from_env(secret_getter: T) -> SignwayServer<T> {
        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build::<_, Body>(https);

        SignwayServer {
            port: u16::from_str(&std::env::var("PORT").unwrap_or("3000".to_string()))
                .expect("failed to parse PORT env variable"),
            secret_getter,
            on_request: Box::new(NoneOnRequest {}),
            on_success: Box::new(NoneOnSuccess {}),
            client,
        }
    }
    pub fn from_port(secret_getter: T, port: u16) -> SignwayServer<T> {
        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build::<_, Body>(https);

        SignwayServer {
            port,
            secret_getter,
            on_request: Box::new(NoneOnRequest {}),
            on_success: Box::new(NoneOnSuccess {}),
            client,
        }
    }

    pub fn on_success(mut self, callback: impl OnSuccess + 'static) -> Self {
        self.on_success = Box::new(callback);
        self
    }

    pub fn on_request(mut self, callback: impl OnRequest + 'static) -> Self {
        self.on_request = Box::new(callback);
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
                async move {
                    if req.method() == Method::OPTIONS {
                        arc_self.route_cors(req).await
                    } else {
                        arc_self.route_gateway(req).await
                    }
                }
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
    use hyper::http::HeaderValue;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU16, Ordering};

    use hyper::StatusCode;
    use reqwest::header::HeaderMap;
    use time::{OffsetDateTime, PrimitiveDateTime};
    use url::Url;

    use crate::_test_tools::tests::InMemorySecretGetter;
    use crate::secret_getter::SecretGetterResult;
    use crate::signing::{ElementsToSign, UrlSigner};

    use super::*;

    fn server_for_testing<const N: usize>(
        config: [(&str, &str); N],
        port: u16,
    ) -> SignwayServer<InMemorySecretGetter> {
        SignwayServer::from_port(
            InMemorySecretGetter(HashMap::from(config.map(|e| {
                (
                    e.0.to_string(),
                    SecretGetterResult {
                        secret: e.1.to_string(),
                        headers_extension: HeaderMap::new(),
                    },
                )
            }))),
            port,
        )
    }

    fn base_request() -> ElementsToSign {
        let now = OffsetDateTime::now_utc();

        ElementsToSign {
            proxy_url: Url::parse("https://postman-echo.com/get").unwrap(),
            expiry: 10,
            datetime: PrimitiveDateTime::new(now.date(), now.time()),
            method: "GET".to_string(),
            headers: None,
            body: None,
        }
    }

    static PORT: AtomicU16 = AtomicU16::new(3000);

    #[tokio::test]
    async fn simple_get_works() {
        let port = PORT.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(server_for_testing([("foo", "foo-secret")], port).start());
        let host = &format!("http://localhost:{port}");

        let signer = UrlSigner::new("foo", "foo-secret");
        let signed_url = signer.get_signed_url(host, &base_request()).unwrap();

        let response = reqwest::Client::new().get(signed_url).send().await.unwrap();

        let status = response.status();
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn options_returns_cors() {
        let port = PORT.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(server_for_testing([("foo", "foo-secret")], port).start());
        let host = &format!("http://localhost:{port}");

        let response = reqwest::Client::new()
            .request(Method::OPTIONS, host)
            .send()
            .await
            .unwrap();

        let status = response.status();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .unwrap_or(&HeaderValue::from_str("NONE").unwrap()),
            "*"
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-headers")
                .unwrap_or(&HeaderValue::from_str("NONE").unwrap()),
            "*"
        );
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-methods")
                .unwrap_or(&HeaderValue::from_str("NONE").unwrap()),
            "*"
        )
    }

    #[tokio::test]
    async fn signed_with_different_secret_does_not_work() {
        let port = PORT.fetch_add(1, Ordering::SeqCst);
        tokio::spawn(server_for_testing([("foo", "foo-secret")], port).start());
        let host = &format!("http://localhost:{port}");

        let bad_signer = UrlSigner::new("foo", "bad-secret");

        let signed_url = bad_signer.get_signed_url(host, &base_request()).unwrap();

        let response = reqwest::Client::new().get(signed_url).send().await.unwrap();

        let status = response.status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
