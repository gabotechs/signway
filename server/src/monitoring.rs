use tracing::error;
use url::Url;

use crate::{
    sw_body::{monitor_sw_body, SwBody},
    BytesTransferredInfo, SignwayServer,
};

impl SignwayServer {
    pub fn subscribe_to_monitoring(&self) -> tokio::sync::broadcast::Receiver<BytesTransferredInfo> {
        self.monitoring_tx.subscribe()
    }

    pub(crate) fn sw_body_with_monitoring(
        &self,
        body: SwBody,
        id: &str,
        proxy_url: &Url,
        is_out: bool,
    ) -> SwBody {
        let producer = self.monitoring_tx.clone();

        let id = id.to_string();
        let proxy_url = proxy_url.clone();
        monitor_sw_body(body, move |d| {
            let info = BytesTransferredInfo {
                id: id.clone(),
                proxy_url: proxy_url.clone(),
                bytes: d,
                kind: match is_out {
                    true => crate::BytesTransferredKind::Out,
                    false => crate::BytesTransferredKind::In,
                },
            };
            let _ = producer
                .send(info)
                .map_err(|err| error!("Error while producing monitoring info: {err}"));
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hyper::Request;
    use tokio::sync::broadcast::error::TryRecvError;

    use crate::_test_tools::tests::{InMemorySecretGetter, ReqBuilder};
    use crate::sw_body::{SwBody, sw_body_to_string};
    use crate::{HeaderMap, SecretGetterResult, SignwayServer};

    fn server() -> SignwayServer {
        SignwayServer::from_env(InMemorySecretGetter(HashMap::from([(
            "foo".to_string(),
            SecretGetterResult {
                secret: "bar".to_string(),
                headers_extension: HeaderMap::new(),
            },
        )])))
    }

    fn req() -> Request<SwBody> {
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

    #[tokio::test]
    async fn test_monitoring() {
        let server = server();
        let mut consumer = server.subscribe_to_monitoring();
        let response = server.handler(req()).await.unwrap();
        assert_eq!(consumer.try_recv().unwrap().bytes, 3);
        assert_eq!(consumer.try_recv().unwrap_err(), TryRecvError::Empty);
        sw_body_to_string(response.into_body(), 400).await.unwrap();
        assert_eq!(consumer.try_recv().unwrap().bytes, 395);
        assert_eq!(consumer.try_recv().unwrap().bytes, 1); // TODO: we does this happen...
        assert_eq!(consumer.try_recv().unwrap_err(), TryRecvError::Empty);
    }
}
