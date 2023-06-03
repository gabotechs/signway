use crate::signing::UnverifiedSignedRequest;
use async_trait::async_trait;

#[async_trait]
pub trait GatewayMiddleware: Sync + Send {
    async fn on_req(&self, req: &UnverifiedSignedRequest);
}
