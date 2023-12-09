use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::u16;

use anyhow::Result;
use async_trait::async_trait;
use hyper::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
};
use hyper::http::{request, response, HeaderValue};
use hyper::Response;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::gateway_callbacks::{CallbackResult, OnRequest, OnSuccess};
use crate::secret_getter::SecretGetter;
use crate::{BytesTransferredInfo, OnBytesTransferred};

#[derive(Clone)]
pub struct SignwayServer {
    pub port: u16,
    pub secret_getter: Arc<dyn SecretGetter>,
    pub on_request: Arc<dyn OnRequest>,
    pub on_success: Arc<dyn OnSuccess>,
    pub on_bytes_transferred: Arc<dyn OnBytesTransferred>,
    pub(crate) monitor_bytes: bool,
    pub(crate) access_control_allow_origin: HeaderValue,
    pub(crate) access_control_allow_methods: HeaderValue,
    pub(crate) access_control_allow_headers: HeaderValue,
}

pub(crate) struct NoneCallback;

#[async_trait]
impl OnRequest for NoneCallback {
    async fn call(&self, _id: &str, _req: &request::Parts) -> CallbackResult {
        CallbackResult::Empty
    }
}

#[async_trait]
impl OnSuccess for NoneCallback {
    async fn call(&self, _id: &str, _res: &response::Parts) -> CallbackResult {
        CallbackResult::Empty
    }
}

#[async_trait]
impl OnBytesTransferred for NoneCallback {
    async fn call(&self, _bytes: usize, _info: BytesTransferredInfo) {}
}

impl SignwayServer {
    pub fn from_env(secret_getter: impl SecretGetter + 'static) -> SignwayServer {
        SignwayServer {
            port: u16::from_str(&std::env::var("PORT").unwrap_or("3000".to_string()))
                .expect("failed to parse PORT env variable"),
            secret_getter: Arc::new(secret_getter),
            on_request: Arc::new(NoneCallback {}),
            on_success: Arc::new(NoneCallback {}),
            on_bytes_transferred: Arc::new(NoneCallback {}),
            monitor_bytes: false,
            access_control_allow_origin: HeaderValue::from_static("*"),
            access_control_allow_headers: HeaderValue::from_static("*"),
            access_control_allow_methods: HeaderValue::from_static("*"),
        }
    }

    pub fn from_port(secret_getter: impl SecretGetter + 'static, port: u16) -> SignwayServer {
        SignwayServer {
            port,
            secret_getter: Arc::new(secret_getter),
            on_request: Arc::new(NoneCallback {}),
            on_success: Arc::new(NoneCallback {}),
            on_bytes_transferred: Arc::new(NoneCallback {}),
            monitor_bytes: false,
            access_control_allow_origin: HeaderValue::from_static("*"),
            access_control_allow_headers: HeaderValue::from_static("*"),
            access_control_allow_methods: HeaderValue::from_static("*"),
        }
    }

    pub fn on_success(mut self, callback: impl OnSuccess + 'static) -> Self {
        self.on_success = Arc::new(callback);
        self
    }

    pub fn on_request(mut self, callback: impl OnRequest + 'static) -> Self {
        self.on_request = Arc::new(callback);
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

    /// Starts the server by maintaining a reference count in each request handle. This will grant
    /// that the memory occupied by the server will be freed after this function has finished and
    /// all the requests have already been handled. Use this function if your application will
    /// continue running after stopping the server. Calling this function has a small runtime cost
    /// for maintaining the reference counting.
    pub async fn start(&'static self) -> Result<()> {
        let in_addr: SocketAddr = ([0, 0, 0, 0], self.port).into();

        let listener = TcpListener::bind(in_addr).await?;

        info!("Server running in {}", in_addr);
        loop {
            let (stream, _) = listener.accept().await?;
            let io = TokioIo::new(stream);

            tokio::spawn(async move {
                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, self)
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

    use hyper::HeaderMap;
    use reqwest::header::HeaderValue;
    use reqwest::{Method, StatusCode};
    use time::{OffsetDateTime, PrimitiveDateTime};
    use url::Url;

    use crate::_test_tools::tests::InMemorySecretGetter;
    use crate::secret_getter::SecretGetterResult;
    use crate::signing::{ElementsToSign, UrlSigner};
    use crate::SignwayServer;

    fn server_for_testing<const N: usize>(config: [(&str, &str); N], port: u16) -> SignwayServer {
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
        let server = server_for_testing([("foo", "foo-secret")], 3000);
        tokio::spawn(server.start());
        let signer = UrlSigner::new("foo", "foo-secret");
        let signed_url = signer
            .get_signed_url("http://localhost:3000", &base_request())
            .unwrap();

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
        let server = server_for_testing([("foo", "foo-secret")], 3001);
        tokio::spawn(server.start());
        let response = reqwest::Client::new()
            .request(Method::OPTIONS, "http://localhost:3001")
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
        let server = server_for_testing([("foo", "foo-secret")], 3002);
        tokio::spawn(server.start());
        let bad_signer = UrlSigner::new("foo", "bad-secret");

        let signed_url = bad_signer
            .get_signed_url("http://localhost:3002", &base_request())
            .unwrap();

        let response = reqwest::Client::new().get(signed_url).send().await.unwrap();

        let status = response.status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
