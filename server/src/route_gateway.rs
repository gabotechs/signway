use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;

use anyhow::anyhow;
use http_body_util::combinators::BoxBody;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::http::request;
use hyper::service::Service;
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::body::body_to_string;
use crate::gateway_callbacks::CallbackResult;
use crate::server::SignwayServer;
use crate::signing::{UnverifiedSignedRequest, UrlSigner};
use crate::signway_response::{
    bad_gateway, bad_request, from_string, internal_server, ok, wrap_full, SignwayResponse,
    SignwayResponseBody,
};
use crate::{BytesTransferredInfo, BytesTransferredKind, GetSecretResponse};

fn parse_content_length(req: &request::Parts) -> anyhow::Result<usize> {
    let content_length = req
        .headers
        .get("content-length")
        .ok_or_else(|| anyhow!("Content-Length header not present"))?;
    Ok(usize::from_str(content_length.to_str()?)?)
}

type SwResponse = SignwayResponse;
type SwError = hyper::Error;
type SwFuture = Pin<Box<dyn Future<Output = Result<SignwayResponse, SwError>> + Send>>;


impl Service<Request<Incoming>> for &SignwayServer {
    type Response = SwResponse;
    type Error = SwError;
    type Future = SwFuture;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        SignwayServer::call(self, req)
    }
}

impl Service<Request<Incoming>> for SignwayServer {
    type Response = SwResponse;
    type Error = SwError;
    type Future = SwFuture;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            if req.method() == Method::OPTIONS {
                return ok();
            }

            let mut unverified_req = match UnverifiedSignedRequest::from_request(&req) {
                Ok(a) => a,
                Err(e) => return bad_request(e),
            };
            let id = unverified_req.info.id;

            let (mut parts, body) = req.into_parts();
            let mut body = BoxBody::new(body);

            if let CallbackResult::EarlyResponse(res) = this.on_request.call(&id, &parts).await {
                return Ok(wrap_full(res));
            };

            let secret = match this.secret_getter.get_secret(&id).await {
                Ok(res) => match res {
                    GetSecretResponse::Secret(secret) => secret,
                    GetSecretResponse::EarlyResponse(early_res) => return Ok(wrap_full(early_res)),
                },
                Err(e) => return internal_server(e),
            };

            let signer = UrlSigner::new(&id, &secret.secret);

            if unverified_req.info.body_is_pending {
                let content_length = match parse_content_length(&parts) {
                    Ok(a) => a,
                    Err(e) => return bad_request(e),
                };
                let body_string =
                    match body_to_string::<SignwayResponseBody>(body, content_length).await {
                        Ok(a) => a,
                        Err(e) => return bad_request(e),
                    };
                unverified_req.elements.body = Some(body_string.clone());
                body = from_string(body_string.into())
            }

            let Some(host) = unverified_req.elements.proxy_url.host() else {
                return bad_request("Invalid host in proxy url");
            };
            let host = host.to_string();

            let proxy_uri = match Uri::from_str(unverified_req.elements.proxy_url.as_str()) {
                Ok(a) => a,
                Err(e) => return bad_request(e),
            };
            parts.uri = proxy_uri;
            parts.headers.insert("host", host.parse().unwrap());
            parts.headers.extend(secret.headers_extension);

            let declared_signature = &unverified_req.info.signature;
            let actual_signature = match signer.get_signature(&unverified_req.elements) {
                Ok(a) => a,
                Err(e) => return internal_server(e),
            };

            if declared_signature != &actual_signature {
                return bad_request("signature mismatch");
            }

            info!("Id {id} provided a valid signature, redirecting the request...",);
            let host = parts.uri.host().expect("uri has no host");
            let port = parts.uri.port_u16().unwrap_or(80);
            let addr = format!("{}:{}", host, port);

            let stream = TcpStream::connect(addr).await.unwrap();
            let io = TokioIo::new(stream);

            let (mut sender, conn) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .handshake(io)
                .await?;

            tokio::task::spawn(async move {
                if let Err(err) = conn.await {
                    warn!("Connection failed: {:?}", err);
                }
            });

            let res = match sender.send_request(Request::from_parts(parts, body)).await {
                Ok(res) => res,
                Err(e) => return bad_gateway(e),
            };
            let (res_parts, res_body) = res.into_parts();
            if let CallbackResult::EarlyResponse(res) = this.on_success.call(&id, &res_parts).await
            {
                return Ok(wrap_full(res));
            };

            let info = BytesTransferredInfo {
                id: id.to_string(),
                proxy_url: unverified_req.elements.proxy_url,
                kind: BytesTransferredKind::Out,
            };

            if this.monitor_bytes {
                Ok(Response::from_parts(res_parts, BoxBody::new(res_body)))
            } else {
                Ok(Response::from_parts(res_parts, BoxBody::new(res_body)))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hyper::{HeaderMap, StatusCode};

    use crate::_test_tools::tests::{json_path, InMemorySecretGetter, ReqBuilder};
    use crate::secret_getter::SecretGetterResult;
    use crate::signing::X_PROXY;

    use super::*;

    fn server() -> SignwayServer {
        SignwayServer::from_env(InMemorySecretGetter(HashMap::from([(
            "foo".to_string(),
            SecretGetterResult {
                secret: "bar".to_string(),
                headers_extension: HeaderMap::try_from(&HashMap::from([(
                    "X-Custom".to_string(),
                    "custom".to_string(),
                )]))
                .unwrap(),
            },
        )])))
    }

    #[tokio::test]
    async fn empty() {
        let response = server()
            .call(
                ReqBuilder::default()
                    .sign("foo", "bar", "http://localhost:3000")
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response = body_to_string(response.into_body(), 9999).await.unwrap();
        assert_eq!(
            json_path::<String>(&response, &["url"]).unwrap(),
            "https://postman-echo.com/get"
        );
        assert_eq!(
            json_path::<String>(&response, &["headers", "x-custom"]).unwrap(),
            "custom"
        );
    }

    #[tokio::test]
    async fn with_query_params() {
        let response = server()
            .call(
                ReqBuilder::default()
                    .query("page", "1")
                    .sign("foo", "bar", "http://localhost:3000")
                    .unwrap()
                    .query(X_PROXY, "https://postman-echo.com/get?page=1")
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response = body_to_string(response.into_body(), 9999).await.unwrap();
        assert_eq!(
            json_path::<String>(&response, &["args", "page"]).unwrap(),
            "1"
        )
    }

    #[tokio::test]
    async fn with_query_params_and_headers_and_body() {
        let response = server()
            .call(
                ReqBuilder::default()
                    .query("page", "1")
                    .header("Content-Length", "3")
                    .post()
                    .body("foo")
                    .sign("foo", "bar", "http://localhost:3000")
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response = body_to_string(response.into_body(), 9999).await.unwrap();
        assert_eq!(
            json_path::<String>(&response, &["headers", "content-length"]).unwrap(),
            "3"
        );
        assert_eq!(json_path::<String>(&response, &["data"]).unwrap(), "foo")
    }

    #[tokio::test]
    async fn with_query_params_and_headers_and_body_and_additional_header() {
        let response = server()
            .call(
                ReqBuilder::default()
                    .query("page", "1")
                    .header("Content-Length", "3")
                    .post()
                    .body("foo")
                    .sign("foo", "bar", "http://localhost:3000")
                    .unwrap()
                    .header("Content-Type", "text/html")
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response = body_to_string(response.into_body(), 9999).await.unwrap();
        assert_eq!(
            json_path::<String>(&response, &["headers", "content-length"]).unwrap(),
            "3"
        );
        assert_eq!(
            json_path::<String>(&response, &["headers", "content-type"]).unwrap(),
            "text/html"
        );
        assert_eq!(json_path::<String>(&response, &["data"]).unwrap(), "foo")
    }

    #[tokio::test]
    async fn with_query_params_and_headers_and_additional_body() {
        let response = server()
            .call(
                ReqBuilder::default()
                    .query("page", "1")
                    .header("Content-Length", "3")
                    .post()
                    .sign("foo", "bar", "http://localhost:3000")
                    .unwrap()
                    .body("foo")
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response = body_to_string(response.into_body(), 9999).await.unwrap();
        assert_eq!(
            json_path::<String>(&response, &["headers", "content-length"]).unwrap(),
            "3"
        );
        assert_eq!(json_path::<String>(&response, &["data"]).unwrap(), "foo")
    }

    #[tokio::test]
    async fn with_invalid_query_param() {
        let response = server()
            .call(
                ReqBuilder::default()
                    .query("page", "1")
                    .sign("foo", "bar", "http://localhost:3000")
                    .unwrap()
                    .query(X_PROXY, "https://postman-echo.com/get?page=2")
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn with_invalid_header() {
        let response = server()
            .call(
                ReqBuilder::default()
                    .query("page", "1")
                    .header("Content-Length", "3")
                    .sign("foo", "bar", "http://localhost:3000")
                    .unwrap()
                    .header("Content-Length", "4")
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn with_invalid_body() {
        let response = server()
            .call(
                ReqBuilder::default()
                    .query("page", "1")
                    .header("Content-Length", "3")
                    .post()
                    .body("foo")
                    .sign("foo", "bar", "http://localhost:3000")
                    .unwrap()
                    .body("bar")
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
