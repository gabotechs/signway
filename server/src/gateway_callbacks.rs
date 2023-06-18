use async_trait::async_trait;
use hyper::{Body, Request, Response};

pub enum CallbackResult {
    EarlyResponse(Response<Body>),
    Empty,
}

#[async_trait]
pub trait OnRequest: Sync + Send {
    async fn call(&self, req: &Request<Body>) -> CallbackResult;
}

#[async_trait]
pub trait OnSuccess: Sync + Send {
    async fn call(&self, res: &Response<Body>) -> CallbackResult;
}

#[cfg(test)]
mod tests {
    use crate::_test_tools::tests::{InMemorySecretGetter, ReqBuilder};
    use crate::gateway_callbacks::{CallbackResult, OnRequest, OnSuccess};
    use crate::{HeaderMap, SecretGetterResult, SignwayServer};
    use async_trait::async_trait;
    use hyper::body::HttpBody;
    use hyper::{Body, Request, Response, StatusCode};
    use std::collections::HashMap;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering::SeqCst;

    fn server() -> SignwayServer<InMemorySecretGetter> {
        SignwayServer::from_env(InMemorySecretGetter(HashMap::from([(
            "foo".to_string(),
            SecretGetterResult {
                secret: "bar".to_string(),
                headers_extension: HeaderMap::new(),
            },
        )])))
    }

    fn req() -> Request<Body> {
        ReqBuilder::default()
            .query("page", "1")
            .header("Content-Length", "3")
            .post()
            .sign("foo", "bar", "http://localhost:3000")
            .unwrap()
            .body("foo")
            .build()
            .unwrap()
    }

    struct SizeCollector<'a>(&'a AtomicU64);

    #[async_trait]
    impl<'a> OnRequest for SizeCollector<'a> {
        async fn call(&self, req: &Request<Body>) -> CallbackResult {
            self.0.fetch_add(req.size_hint().exact().unwrap(), SeqCst);
            CallbackResult::Empty
        }
    }

    #[async_trait]
    impl<'a> OnSuccess for SizeCollector<'a> {
        async fn call(&self, res: &Response<Body>) -> CallbackResult {
            self.0.fetch_add(res.size_hint().exact().unwrap(), SeqCst);
            CallbackResult::Empty
        }
    }

    #[tokio::test]
    async fn test_on_request() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let size_collector = SizeCollector(&COUNTER);

        let response = server()
            .on_request(size_collector)
            .route_gateway(req())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(COUNTER.load(SeqCst), 3);
    }

    #[tokio::test]
    async fn test_on_success() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let size_collector = SizeCollector(&COUNTER);

        let response = server()
            .on_success(size_collector)
            .route_gateway(req())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(COUNTER.load(SeqCst), 396);
    }
}
