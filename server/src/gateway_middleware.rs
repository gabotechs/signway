use std::fmt::Display;

use async_trait::async_trait;
pub use hyper::StatusCode;

use crate::signing::UnverifiedSignedRequest;

/// Response from a gateway middleware. This response is
/// optional, if a gateway middleware decided to return
/// Some(GatewayMiddlewareResponse) then the gateway will
/// abort doing further work and will return this response.
#[derive(Debug, Clone)]
pub struct GatewayMiddlewareResponse {
    pub status: StatusCode,
    pub message: String,
}

#[async_trait]
pub trait GatewayMiddleware: Sync + Send {
    async fn on_req(
        &self,
        req: &UnverifiedSignedRequest,
    ) -> Result<Option<GatewayMiddlewareResponse>, Box<dyn Display>>;
}
