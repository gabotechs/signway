use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::u16;

use anyhow::Result;
use async_trait::async_trait;
use hyper::client::HttpConnector;
use hyper::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
};
use hyper::http::HeaderValue;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, StatusCode};
use hyper_tls::HttpsConnector;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::gateway_callbacks::{CallbackResult, OnRequest, OnSuccess};
use crate::secret_getter::SecretGetter;
use crate::{BytesTransferredInfo, OnBytesTransferred};

fn ok() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .unwrap()
}

pub struct SignwayServer<T: SecretGetter + 'static> {
    pub port: u16,
    pub secret_getter: T,
    pub on_request: Box<dyn OnRequest>,
    pub on_success: Box<dyn OnSuccess>,
    pub on_bytes_transferred: Arc<dyn OnBytesTransferred>,
    pub(crate) monitor_bytes: bool,
    pub(crate) client: hyper::Client<HttpsConnector<HttpConnector>, Body>,
    pub(crate) access_control_allow_origin: HeaderValue,
    pub(crate) access_control_allow_methods: HeaderValue,
    pub(crate) access_control_allow_headers: HeaderValue,
}

pub(crate) struct NoneCallback;

#[async_trait]
impl OnRequest for NoneCallback {
    async fn call(&self, _id: &str, _req: &Request<Body>) -> CallbackResult {
        CallbackResult::Empty
    }
}

#[async_trait]
impl OnSuccess for NoneCallback {
    async fn call(&self, _id: &str, _res: &Response<Body>) -> CallbackResult {
        CallbackResult::Empty
    }
}

#[async_trait]
impl OnBytesTransferred for NoneCallback {
    async fn call(&self, _bytes: usize, _info: BytesTransferredInfo) {}
}

impl<T: SecretGetter> SignwayServer<T> {
    pub fn from_env(secret_getter: T) -> SignwayServer<T> {
        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build::<_, Body>(https);

        SignwayServer {
            port: u16::from_str(&std::env::var("PORT").unwrap_or("3000".to_string()))
                .expect("failed to parse PORT env variable"),
            secret_getter,
            on_request: Box::new(NoneCallback {}),
            on_success: Box::new(NoneCallback {}),
            on_bytes_transferred: Arc::new(NoneCallback {}),
            monitor_bytes: false,
            access_control_allow_origin: HeaderValue::from_static("*"),
            access_control_allow_headers: HeaderValue::from_static("*"),
            access_control_allow_methods: HeaderValue::from_static("*"),
            client,
        }
    }
    pub fn from_port(secret_getter: T, port: u16) -> SignwayServer<T> {
        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build::<_, Body>(https);

        SignwayServer {
            port,
            secret_getter,
            on_request: Box::new(NoneCallback {}),
            on_success: Box::new(NoneCallback {}),
            on_bytes_transferred: Arc::new(NoneCallback {}),
            monitor_bytes: false,
            access_control_allow_origin: HeaderValue::from_static("*"),
            access_control_allow_headers: HeaderValue::from_static("*"),
            access_control_allow_methods: HeaderValue::from_static("*"),
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

    pub fn on_bytes_transferred(mut self, callback: impl OnBytesTransferred + 'static) -> Self {
        self.on_bytes_transferred = Arc::new(callback);
        self.monitor_bytes = true;
        self
    }

    pub fn access_control_allow_origin(mut self, value: &str) -> Result<Self> {
        self.access_control_allow_origin = value.parse()?;
        Ok(self)
    }

    pub fn access_control_allow_methods(mut self, value: &str) -> Result<Self> {
        self.access_control_allow_methods = value.parse()?;
        Ok(self)
    }

    pub fn access_control_allow_headers(mut self, value: &str) -> Result<Self> {
        self.access_control_allow_headers = value.parse()?;
        Ok(self)
    }

    fn with_cors_headers<B>(&self, mut res: Response<B>) -> Response<B> {
        let h = res.headers_mut();
        h.insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            self.access_control_allow_origin.clone(),
        );
        h.insert(
            ACCESS_CONTROL_ALLOW_METHODS,
            self.access_control_allow_methods.clone(),
        );
        h.insert(
            ACCESS_CONTROL_ALLOW_HEADERS,
            self.access_control_allow_headers.clone(),
        );
        res
    }

    pub async fn start(&'static self) -> Result<()> {
        let in_addr: SocketAddr = ([0, 0, 0, 0], self.port).into();

        let listener = TcpListener::bind(in_addr).await?;

        info!("Server running in {}", in_addr);
        loop {
            let (stream, _) = listener.accept().await?;

            let service = service_fn(move |req| async move {
                let res = if req.method() == Method::OPTIONS {
                    Ok(ok())
                } else {
                    self.route_gateway(req).await
                };
                if let Ok(res) = res {
                    Ok(self.with_cors_headers(res))
                } else {
                    res
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
    use std::collections::HashMap;

    use hyper::http::HeaderValue;
    use hyper::StatusCode;
    use lazy_static::lazy_static;
    use reqwest::header::HeaderMap;
    use time::{OffsetDateTime, PrimitiveDateTime};
    use url::Url;

    use crate::_test_tools::tests::InMemorySecretGetter;
    use crate::secret_getter::SecretGetterResult;
    use crate::signing::{ElementsToSign, UrlSigner};

    use super::*;

    lazy_static! {
        static ref SERVER: SignwayServer<InMemorySecretGetter> =
            server_for_testing([("foo", "foo-secret")], 3000);
    }

    async fn init() -> &'static str {
        tokio::spawn(SERVER.start());
        "http://localhost:3000"
    }

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

    #[tokio::test]
    async fn simple_get_works() {
        let host = init().await;
        let signer = UrlSigner::new("foo", "foo-secret");
        let signed_url = signer.get_signed_url(host, &base_request()).unwrap();

        let response = reqwest::Client::new().get(signed_url).send().await.unwrap();

        let status = response.status();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .unwrap_or(&HeaderValue::from_str("NONE").unwrap()),
            "*"
        );
    }

    #[tokio::test]
    async fn options_returns_cors() {
        let host = init().await;
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
        );
    }

    #[tokio::test]
    async fn signed_with_different_secret_does_not_work() {
        let host = init().await;
        let bad_signer = UrlSigner::new("foo", "bad-secret");

        let signed_url = bad_signer.get_signed_url(host, &base_request()).unwrap();

        let response = reqwest::Client::new().get(signed_url).send().await.unwrap();

        let status = response.status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
