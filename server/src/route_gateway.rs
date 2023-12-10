use std::str::FromStr;

use anyhow::anyhow;
use hyper::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
};
use hyper::http::request;
use hyper::{Method, Request, Response, Result, Uri};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy;
use hyper_util::rt::TokioExecutor;
use tracing::info;

use crate::gateway_callbacks::CallbackResult;
use crate::server::SignwayServer;
use crate::signing::{UnverifiedSignedRequest, UrlSigner};
use crate::sw_body::{
    bad_gateway, bad_request, full_response_into_sw_response, incoming_response_into_sw_response,
    internal_server, monitor_sw_body, ok, sw_body_from_string, sw_body_to_string, SwBody,
};
use crate::{BytesTransferredInfo, GetSecretResponse};

fn parse_content_length(req: &request::Parts) -> anyhow::Result<usize> {
    let content_length = req
        .headers
        .get("content-length")
        .ok_or_else(|| anyhow!("Content-Length header not present"))?;
    Ok(usize::from_str(content_length.to_str()?)?)
}

impl SignwayServer {
    fn with_cors_headers<B>(&self, mut res: Response<B>) -> Response<B> {
        let h = res.headers_mut();
        h.insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            self.access_control_allow_origin.clone(),
        );
        h.insert(
            ACCESS_CONTROL_ALLOW_METHODS,
            self.access_control_allow_methods.clone(),
        );
        h.insert(
            ACCESS_CONTROL_ALLOW_HEADERS,
            self.access_control_allow_headers.clone(),
        );
        res
    }

    pub(crate) async fn handler_with_cors(&self, req: Request<SwBody>) -> Result<Response<SwBody>> {
        self.handler(req)
            .await
            .map(|res| self.with_cors_headers(res))
    }

    pub(crate) async fn handler(&self, req: Request<SwBody>) -> Result<Response<SwBody>> {
        if req.method() == Method::OPTIONS {
            return ok();
        }

        // Step 1: gather the elements in the request that should taken into account for
        //  calculating the signature.
        let (mut req_parts, mut req_body) = req.into_parts();
        let mut unverified_req = match UnverifiedSignedRequest::try_from(&req_parts) {
            Ok(a) => a,
            Err(e) => return bad_request(e),
        };
        let id = unverified_req.info.id.clone();
        let proxy_url = unverified_req.elements.proxy_url.clone();
        let proxy_uri = match Uri::from_str(proxy_url.as_str()) {
            Ok(a) => a,
            Err(e) => return bad_request(e),
        };
        let Some(host) = proxy_url.host() else {
            return bad_request("Invalid host in proxy url");
        };
        if let CallbackResult::EarlyResponse(res) = self.on_request.call(&id, &req_parts).await {
            return Ok(full_response_into_sw_response(res));
        };

        // Step 2: retrieve the secret for the specific ID declared in the request.
        let secret = match self.secret_getter.get_secret(&id).await {
            Ok(res) => match res {
                GetSecretResponse::Secret(secret) => secret,
                GetSecretResponse::EarlyResponse(early_res) => {
                    return Ok(full_response_into_sw_response(early_res));
                }
            },
            Err(e) => return internal_server(e),
        };

        // Step 3: At this point the request body was not retrieved, and maybe it should be taken
        //  into account for calculating the signature, so retrieve it now. We want to delay this
        //  action as much as possible, as it's potentially expensive.
        if unverified_req.body_is_pending() {
            let content_length = match parse_content_length(&req_parts) {
                Ok(a) => a,
                Err(e) => return bad_request(e),
            };
            let body_string = match sw_body_to_string(req_body, content_length).await {
                Ok(a) => a,
                Err(e) => return bad_request(e),
            };
            unverified_req.replace_body(body_string.clone());
            req_body = sw_body_from_string(body_string)
        }

        // Step 4: Now that all the elements that should be signed are in place, calculate the
        //  signature and check that it matches the declared one.
        let signer = UrlSigner::new(&id, &secret.secret);
        let actual_signature = match signer.get_signature(&unverified_req.elements) {
            Ok(a) => a,
            Err(e) => return internal_server(e),
        };
        if unverified_req.info.signature != actual_signature {
            return bad_request("signature mismatch");
        }
        info!("Id {id} provided a valid signature, redirecting the request...",);

        // Step 5: The signature was verified, so let's proxy the request to the specified host.
        let host = host.to_string();
        req_parts.uri = proxy_uri;
        req_parts.headers.insert("host", host.parse().unwrap());
        req_parts.headers.extend(secret.headers_extension);
        if self.monitor_bytes {
            let on_bytes_transferred = self.on_bytes_transferred.clone();
            let id = id.clone();
            let proxy_url = proxy_url.clone();
            req_body = monitor_sw_body(req_body, move |d| {
                let info = BytesTransferredInfo::in_kind(&id, &proxy_url);
                let on_bytes_transferred = on_bytes_transferred.clone();
                tokio::spawn(async move { on_bytes_transferred.call(d, info).await });
            })
        }
        let req = Request::from_parts(req_parts, req_body);
        let client = legacy::Client::builder(TokioExecutor::new()).build(HttpsConnector::new());
        let res = match client.request(req).await {
            Ok(a) => a,
            Err(err) => return bad_gateway(err),
        };
        let (res_parts, mut res_body) = incoming_response_into_sw_response(res).into_parts();
        if let CallbackResult::EarlyResponse(res) = self.on_success.call(&id, &res_parts).await {
            return Ok(full_response_into_sw_response(res));
        };
        if self.monitor_bytes {
            let on_bytes_transferred = self.on_bytes_transferred.clone();
            res_body = monitor_sw_body(res_body, move |d| {
                let info = BytesTransferredInfo::out_kind(&id, &proxy_url);
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
