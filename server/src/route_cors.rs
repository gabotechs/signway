use crate::{SecretGetter, SignwayServer};
use hyper::{Body, Request, Response};

impl<T: SecretGetter> SignwayServer<T> {
    pub(crate) async fn route_cors(&self, _req: Request<Body>) -> hyper::Result<Response<Body>> {
        Ok(Response::builder()
            .status(200)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "*")
            .header("Access-Control-Allow-Headers", "*")
            .body(Body::empty())
            .unwrap())
    }
}
