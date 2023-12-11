use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::http::HeaderValue;
use hyper::service::service_fn;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::gateway_callbacks::{OnRequest, OnSuccess};
use crate::secret_getter::SecretGetter;
use crate::sw_body::incoming_request_into_sw_request;
use crate::OnBytesTransferred;

#[derive(Clone)]
pub struct SignwayServer {
    pub port: u16,
    pub secret_getter: Arc<dyn SecretGetter>,
    pub on_request: Option<Arc<dyn OnRequest>>,
    pub on_success: Option<Arc<dyn OnSuccess>>,
    pub on_bytes_transferred: Option<Arc<dyn OnBytesTransferred>>,
    pub(crate) access_control_allow_origin: HeaderValue,
    pub(crate) access_control_allow_methods: HeaderValue,
    pub(crate) access_control_allow_headers: HeaderValue,
}

impl SignwayServer {
    pub fn from_env(secret_getter: impl SecretGetter + 'static) -> SignwayServer {
        SignwayServer {
            port: u16::from_str(&std::env::var("PORT").unwrap_or("3000".to_string()))
                .expect("failed to parse PORT env variable"),
            secret_getter: Arc::new(secret_getter),
            on_request: None,
            on_success: None,
            on_bytes_transferred: None,
            access_control_allow_origin: HeaderValue::from_static("*"),
            access_control_allow_headers: HeaderValue::from_static("*"),
            access_control_allow_methods: HeaderValue::from_static("*"),
        }
    }

    pub fn from_port(secret_getter: impl SecretGetter + 'static, port: u16) -> SignwayServer {
        SignwayServer {
            port,
            secret_getter: Arc::new(secret_getter),
            on_request: None,
            on_success: None,
            on_bytes_transferred: None,
            access_control_allow_origin: HeaderValue::from_static("*"),
            access_control_allow_headers: HeaderValue::from_static("*"),
            access_control_allow_methods: HeaderValue::from_static("*"),
        }
    }

    pub fn on_success(mut self, callback: impl OnSuccess + 'static) -> Self {
        self.on_success = Some(Arc::new(callback));
        self
    }

    pub fn on_request(mut self, callback: impl OnRequest + 'static) -> Self {
        self.on_request = Some(Arc::new(callback));
        self
    }

    pub fn on_bytes_transferred(mut self, callback: impl OnBytesTransferred + 'static) -> Self {
        self.on_bytes_transferred = Some(Arc::new(callback));
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

    /// Starts the server by maintaining a reference count in each request handle. This will grant
    /// that the memory occupied by the server will be freed after this function has finished and
    /// all the requests have already been handled. Use this function if your application will
    /// continue running after stopping the server. Calling this function has a small runtime cost
    /// for maintaining the reference counting.
    pub async fn start(&self) -> Result<()> {
        let in_addr: SocketAddr = ([0, 0, 0, 0], self.port).into();

        let listener = TcpListener::bind(in_addr).await?;

        info!("Server running in {}", in_addr);
        loop {
            let (stream, _) = listener.accept().await?;
            let io = TokioIo::new(stream);

            let self_clone = self.clone();

            let handler = service_fn(move |req: Request<Incoming>| {
                let req = incoming_request_into_sw_request(req);
                let self_clone = self_clone.clone();
                async move { self_clone.handler_with_cors(req).await }
            });

            tokio::spawn(async move {
                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, handler)
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
    use crate::signing::{ElementsToSign, SignedBody, UrlSigner};
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
            body: SignedBody::None,
        }
    }

    #[tokio::test]
    async fn simple_get_works() {
        let server = server_for_testing([("foo", "foo-secret")], 3000);
        tokio::spawn(async move { server.start().await });
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
        tokio::spawn(async move { server.start().await });
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
        tokio::spawn(async move { server.start().await });
        let bad_signer = UrlSigner::new("foo", "bad-secret");

        let signed_url = bad_signer
            .get_signed_url("http://localhost:3002", &base_request())
            .unwrap();

        let response = reqwest::Client::new().get(signed_url).send().await.unwrap();

        let status = response.status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
