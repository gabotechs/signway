use anyhow::anyhow;
use std::str::FromStr;

use hyper::body::Body;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use tracing::{error, info};

use crate::body::{body_to_string, string_to_body};
use crate::secret_getter::SecretGetter;
use crate::server::Server;
use crate::signing::{SignRequest, UrlSigner};

fn bad_request(e: impl Into<anyhow::Error>) -> Response<Body> {
    info!("Answering bad request: {}", e.into());
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::empty())
        .unwrap()
}

fn internal_server(e: impl Into<anyhow::Error>) -> Response<Body> {
    error!("Answering internal server error: {}", e.into());
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::empty())
        .unwrap()
}

fn bad_gateway(e: impl Into<anyhow::Error>) -> Response<Body> {
    let err = e.into();
    error!("Answering bad gateway {}", err);
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(string_to_body(&err.to_string()))
        .unwrap()
}

impl<T: SecretGetter> Server<T> {
    fn parse_content_length<B>(req: &Request<B>) -> anyhow::Result<usize> {
        let content_length = req
            .headers()
            .get("content-length")
            .ok_or_else(|| anyhow!("Content-Length header not present"))?;
        Ok(usize::from_str(content_length.to_str()?)?)
    }

    pub async fn route_gateway(&self, mut req: Request<Body>) -> hyper::Result<Response<Body>> {
        let (mut to_sign, info) = match SignRequest::from_signed_request(&req) {
            Ok((a, b)) => (a, b),
            Err(e) => return Ok(bad_request(e)),
        };

        let secret = match self.secret_getter.get_secret(&info.id).await {
            Ok(a) => a,
            Err(e) => return Ok(internal_server(e)),
        };

        let Some(secret) = secret else {
            return Ok(bad_request(anyhow!("Missing secret")));
        };

        let signer = UrlSigner::new(&info.id, &secret, self.self_host.clone());

        if info.include_body {
            let content_length = match Self::parse_content_length(&req) {
                Ok(a) => a,
                Err(e) => return Ok(bad_request(e)),
            };
            let (parts, body) = req.into_parts();
            let body = match body_to_string(body, content_length).await {
                Ok(a) => a,
                Err(e) => return Ok(bad_request(e)),
            };
            req = Request::from_parts(parts, string_to_body(&body));
            to_sign.body = Some(body);
        }

        let Some(host) = to_sign.proxy_url.host() else {
            return Ok(bad_request(anyhow!("Invalid host in proxy url")))
        };
        let host = host.to_string();

        let proxy_uri = match Uri::from_str(to_sign.proxy_url.as_str()) {
            Ok(a) => a,
            Err(e) => return Ok(bad_request(e)),
        };
        *req.uri_mut() = proxy_uri;
        req.headers_mut().insert("host", host.parse().unwrap());

        let declared_signature = &info.signature;
        let actual_signature = match signer.get_signature(&to_sign) {
            Ok(a) => a,
            Err(e) => return Ok(internal_server(e)),
        };

        if declared_signature != &actual_signature {
            return Ok(bad_request(anyhow!("signature mismatch")));
        }

        let https = HttpsConnector::new();
        let client = hyper::Client::builder().build::<_, Body>(https);
        match client.request(req).await {
            Ok(a) => Ok(a),
            Err(e) => Ok(bad_gateway(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::_test_tools::tests::{json_path, ReqBuilder};
    use crate::secret_getter::InMemorySecretGetter;
    use crate::signing::X_PROXY;
    use std::collections::HashMap;
    use url::Url;

    fn server() -> Server<InMemorySecretGetter> {
        Server {
            port: 0,
            self_host: Url::parse("http://localhost").unwrap(),
            secret_getter: InMemorySecretGetter(HashMap::from([(
                "foo".to_string(),
                "bar".to_string(),
            )])),
        }
    }

    #[tokio::test]
    async fn empty() {
        let response = server()
            .route_gateway(
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
        )
    }

    #[tokio::test]
    async fn with_query_params() {
        let response = server()
            .route_gateway(
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
            .route_gateway(
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
            .route_gateway(
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
            .route_gateway(
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
            .route_gateway(
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
            .route_gateway(
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
            .route_gateway(
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
