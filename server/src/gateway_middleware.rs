use async_trait::async_trait;
use hyper::{Body, Request};

#[async_trait]
pub trait GatewayMiddleware: Sync + Send {
    async fn on_req(&self, req: &Request<Body>);
}
