use std::error::Error;

use async_trait::async_trait;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::http::Response;
pub use hyper::HeaderMap;

#[derive(Clone)]
pub struct SecretGetterResult {
    pub secret: String,
    pub headers_extension: HeaderMap,
}

pub enum GetSecretResponse {
    EarlyResponse(Response<Full<Bytes>>),
    Secret(SecretGetterResult),
}

#[async_trait]
pub trait SecretGetter: Send + Sync {
    async fn get_secret(&self, id: &str) -> Result<GetSecretResponse, Box<dyn Error>>;
}
