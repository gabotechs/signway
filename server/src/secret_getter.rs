use std::fmt::Display;

use async_trait::async_trait;
use hyper::http::Response;
use hyper::Body;
pub use hyper::HeaderMap;

#[derive(Clone)]
pub struct SecretGetterResult {
    pub secret: String,
    pub headers_extension: HeaderMap,
}

pub enum GetSecretResponse {
    EarlyResponse(Response<Body>),
    Secret(SecretGetterResult),
}

#[async_trait]
pub trait SecretGetter: Send + Sync {
    type Error: Display;

    async fn get_secret(&self, id: &str) -> Result<GetSecretResponse, Self::Error>;
}
