use std::fmt::Display;

use async_trait::async_trait;

// TODO: I am force to expose this, but I think I shouldn't,
//  maybe a good way of doing this is to hide this types and provide
//  a constructor from a Hashmap or something like that.
pub use hyper::http::{HeaderName, HeaderValue};
pub use hyper::HeaderMap;

#[derive(Clone)]
pub struct SecretGetterResult {
    pub secret: String,
    pub headers_extension: HeaderMap,
}

#[async_trait]
pub trait SecretGetter: Send + Sync {
    type Error: Display;

    async fn get_secret(&self, id: &str) -> Result<Option<SecretGetterResult>, Self::Error>;
}
