use std::str::FromStr;

use anyhow::anyhow;
use hyper::client::conn::http1;
use hyper::http::request;
use hyper::{Method, Request, Response, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{info, warn};

use crate::gateway_callbacks::CallbackResult;
use crate::server::SignwayServer;
use crate::signing::{UnverifiedSignedRequest, UrlSigner};
use crate::sw_body::{
    bad_gateway, bad_request, full_response_into_sw_response,
    incoming_response_into_sw_response, internal_server,
    monitor_sw_body, ok, sw_body_to_string, SwBody, sw_body_from_string,
};
use crate::{BytesTransferredInfo, BytesTransferredKind, GetSecretResponse};

fn parse_content_length(req: &request::Parts) -> anyhow::Result<usize> {
    let content_length = req
        .headers
        .get("content-length")
        .ok_or_else(|| anyhow!("Content-Length header not present"))?;
    Ok(usize::from_str(content_length.to_str()?)?)
}

impl SignwayServer {
    pub(crate) async fn handler<'a>(
        &self,
        req: Request<SwBody<'_>>,
    ) -> Result<Response<SwBody<'a>>, hyper::Error> {
        if req.method() == Method::OPTIONS {
            return ok();
        }

        let mut unverified_req = match UnverifiedSignedRequest::from_request(&req) {
            Ok(a) => a,
            Err(e) => return bad_request(e),
        };
        let id = unverified_req.info.id;

        let (mut req_parts, mut req_body) = req.into_parts();

        if let CallbackResult::EarlyResponse(res) = self.on_request.call(&id, &req_parts).await {
            return Ok(full_response_into_sw_response(res));
        };

        let secret = match self.secret_getter.get_secret(&id).await {
            Ok(res) => match res {
                GetSecretResponse::Secret(secret) => secret,
                GetSecretResponse::EarlyResponse(early_res) => {
                    return Ok(full_response_into_sw_response(early_res))
                }
            },
            Err(e) => return internal_server(e),
        };

        let signer = UrlSigner::new(&id, &secret.secret);

        if unverified_req.info.body_is_pending {
            let content_length = match parse_content_length(&req_parts) {
                Ok(a) => a,
                Err(e) => return bad_request(e),
            };
            let body_string = match sw_body_to_string(req_body, content_length).await {
                Ok(a) => a,
                Err(e) => return bad_request(e),
            };
            unverified_req.elements.body = Some(body_string.clone());
            req_body = sw_body_from_string(body_string)
        }

        let Some(host) = unverified_req.elements.proxy_url.host() else {
            return bad_request("Invalid host in proxy url");
        };
        let host = host.to_string();

        let proxy_uri = match Uri::from_str(unverified_req.elements.proxy_url.as_str()) {
            Ok(a) => a,
            Err(e) => return bad_request(e),
        };
        req_parts.uri = proxy_uri;
        req_parts.headers.insert("host", host.parse().unwrap());
        req_parts.headers.extend(secret.headers_extension);

        let declared_signature = &unverified_req.info.signature;
        let actual_signature = match signer.get_signature(&unverified_req.elements) {
            Ok(a) => a,
            Err(e) => return internal_server(e),
        };

        if declared_signature != &actual_signature {
            return bad_request("signature mismatch");
        }

        info!("Id {id} provided a valid signature, redirecting the request...",);
        let host = req_parts.uri.host().expect("uri has no host");
        let port = req_parts.uri.port_u16().unwrap_or(80);
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

        if self.monitor_bytes {
            let on_bytes_transferred = self.on_bytes_transferred.clone();
            let info = BytesTransferredInfo {
                id: id.to_string(),
                proxy_url: unverified_req.elements.proxy_url.clone(),
                kind: BytesTransferredKind::In,
            };
            req_body = monitor_sw_body(req_body, move |d| {
                let info = info.clone();
                let on_bytes_transferred = on_bytes_transferred.clone();
                tokio::spawn(async move { on_bytes_transferred.call(d, info).await });
            })
        }

        let req = Request::from_parts(req_parts, req_body);

        let res = match sender.send_request(req).await {
            Ok(res) => incoming_response_into_sw_response(res),
            Err(e) => return bad_gateway(e),
        };

        let (res_parts, mut res_body) = res.into_parts();
        if let CallbackResult::EarlyResponse(res) = self.on_success.call(&id, &res_parts).await {
            return Ok(full_response_into_sw_response(res));
        };

        if self.monitor_bytes {
            let on_bytes_transferred = self.on_bytes_transferred.clone();
            let info = BytesTransferredInfo {
                id: id.to_string(),
                proxy_url: unverified_req.elements.proxy_url,
                kind: BytesTransferredKind::In,
            };

            res_body = monitor_sw_body(res_body, move |d| {
                let info = info.clone();
                let on_bytes_transferred = on_bytes_transferred.clone();
                tokio::spawn(async move { on_bytes_transferred.call(d, info).await });
            })
        }

        Ok(Response::from_parts(res_parts, res_body))
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
            .handler(
                ReqBuilder::default()
                    .sign("foo", "bar", "http://localhost:3000")
                    .unwrap()
                    .build()
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let response = sw_body_to_string(response.into_body(), 9999).await.unwrap();
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
            .handler(
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
        let response = sw_body_to_string(response.into_body(), 9999).await.unwrap();
        assert_eq!(
            json_path::<String>(&response, &["args", "page"]).unwrap(),
            "1"
        )
    }

    #[tokio::test]
    async fn with_query_params_and_headers_and_body() {
        let response = server()
            .handler(
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
        let response = sw_body_to_string(response.into_body(), 9999).await.unwrap();
        assert_eq!(
            json_path::<String>(&response, &["headers", "content-length"]).unwrap(),
            "3"
        );
        assert_eq!(json_path::<String>(&response, &["data"]).unwrap(), "foo")
    }

    #[tokio::test]
    async fn with_query_params_and_headers_and_body_and_additional_header() {
        let response = server()
            .handler(
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
        let response = sw_body_to_string(response.into_body(), 9999).await.unwrap();
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
            .handler(
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
        let response = sw_body_to_string(response.into_body(), 9999).await.unwrap();
        assert_eq!(
            json_path::<String>(&response, &["headers", "content-length"]).unwrap(),
            "3"
        );
        assert_eq!(json_path::<String>(&response, &["data"]).unwrap(), "foo")
    }

    #[tokio::test]
    async fn with_invalid_query_param() {
        let response = server()
            .handler(
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
            .handler(
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
            .handler(
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
