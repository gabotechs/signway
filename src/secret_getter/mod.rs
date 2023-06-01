use async_trait::async_trait;
use hyper::HeaderMap;

pub use in_memory_secret_getter::*;

mod in_memory_secret_getter;

#[derive(Clone)]
pub struct SecretGetterResult {
    pub secret: String,
    pub headers_extension: HeaderMap,
}

#[async_trait]
pub trait SecretGetter: Send + Sync {
    async fn get_secret(&self, id: &str) -> anyhow::Result<Option<SecretGetterResult>>;
}
