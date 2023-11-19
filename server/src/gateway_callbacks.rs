use std::fmt::{Display, Formatter};

use async_trait::async_trait;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::http::{request, response};
use hyper::Response;
use url::Url;

pub enum CallbackResult {
    EarlyResponse(Response<Full<Bytes>>),
    Empty,
}

#[async_trait]
pub trait OnRequest: Sync + Send {
    async fn call(&self, id: &str, req: &request::Parts) -> CallbackResult;
}

#[async_trait]
pub trait OnSuccess: Sync + Send {
    async fn call(&self, id: &str, res: &response::Parts) -> CallbackResult;
}

#[derive(Debug, Clone)]
pub enum BytesTransferredKind {
    In,
    Out,
}

impl Display for BytesTransferredKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                BytesTransferredKind::In => "IN",
                BytesTransferredKind::Out => "OUT",
            }
        )
    }
}

#[derive(Clone, Debug)]
pub struct BytesTransferredInfo {
    pub id: String,
    pub proxy_url: Url,
    pub kind: BytesTransferredKind,
}

#[async_trait]
pub trait OnBytesTransferred: Sync + Send {
    async fn call(&self, bytes: usize, info: BytesTransferredInfo);
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering::SeqCst;

    use async_trait::async_trait;
    use http_body_util::Full;
    use hyper::body::{Bytes, Incoming};
    use hyper::http::{request, response};
    use hyper::service::Service;
    use hyper::{Request, StatusCode};

    use crate::_test_tools::tests::{InMemorySecretGetter, ReqBuilder};
    use crate::body::body_to_string;
    use crate::gateway_callbacks::{CallbackResult, OnRequest, OnSuccess};
    use crate::signway_response::SignwayResponse;
    use crate::{
        BytesTransferredInfo, HeaderMap, OnBytesTransferred, SecretGetterResult, SignwayServer,
    };

    fn server() -> SignwayServer {
        SignwayServer::from_env(InMemorySecretGetter(HashMap::from([(
            "foo".to_string(),
            SecretGetterResult {
                secret: "bar".to_string(),
                headers_extension: HeaderMap::new(),
            },
        )])))
    }

    fn req() -> Request<Incoming> {
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
        async fn call(&self, _id: &str, req: &request::Parts) -> CallbackResult {
            let size: &str = req.headers.get("content-length").unwrap().to_str().unwrap();
            self.0.fetch_add(u64::from_str(size).unwrap(), SeqCst);
            CallbackResult::Empty
        }
    }

    #[async_trait]
    impl<'a> OnSuccess for SizeCollector<'a> {
        async fn call(&self, _id: &str, res: &response::Parts) -> CallbackResult {
            let size: &str = res.headers.get("content-length").unwrap().to_str().unwrap();
            self.0.fetch_add(u64::from_str(size).unwrap(), SeqCst);
            CallbackResult::Empty
        }
    }

    #[async_trait]
    impl<'a> OnBytesTransferred for SizeCollector<'a> {
        async fn call(&self, bytes: usize, _info: BytesTransferredInfo) {
            self.0.fetch_add(bytes as u64, SeqCst);
        }
    }

    #[tokio::test]
    async fn test_on_request() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let size_collector = SizeCollector(&COUNTER);

        let response = server()
            .on_request(size_collector)
            .call(req())
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
            .call(req())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(COUNTER.load(SeqCst), 396);
    }

    #[tokio::test]
    async fn test_on_bytes_transferred() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let size_collector = SizeCollector(&COUNTER);

        let response = server()
            .on_bytes_transferred(size_collector)
            .call(req())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(COUNTER.load(SeqCst), 3);
        body_to_string::<SignwayResponse>(response.into_body(), 396)
            .await
            .unwrap();
        assert_eq!(COUNTER.load(SeqCst), 399);
    }
}
