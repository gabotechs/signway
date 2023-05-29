use anyhow::anyhow;
use std::str::FromStr;

use hyper::body::Body;
use hyper::{Request, Response, StatusCode, Uri};
use tokio::net::TcpStream;

use crate::body::{body_to_string, string_to_body};
use crate::secret_getter::SecretGetter;
use crate::server::Server;
use crate::signing::{SignRequest, UrlSigner};

fn bad_request() -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(Body::empty())
        .unwrap()
}

fn internal_server(e: impl Into<anyhow::Error>) -> Response<Body> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::empty())
        .unwrap()
}

fn bad_gateway(e: impl Into<anyhow::Error>) -> Response<Body> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(string_to_body(&e.into().to_string()))
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

    async fn proxy_request(
        host: &str,
        port: u16,
        req: Request<Body>,
    ) -> hyper::Result<Response<Body>> {
        let client_stream = match TcpStream::connect(format!("{host}:{port}")).await {
            Ok(a) => a,
            Err(e) => return Ok(bad_gateway(e)),
        };
        let (mut sender, conn) = match hyper::client::conn::handshake(client_stream).await {
            Ok((a, b)) => (a, b),
            Err(e) => return Ok(bad_gateway(e)),
        };
        tokio::spawn(async {
            if let Err(err) = conn.await {
                // todo: how to handle this.
                println!("Connection failed: {:?}", err);
            } else {
                println!("Connection established");
            }
        });

        sender.send_request(req).await
    }

    pub async fn route_gateway(&self, mut req: Request<Body>) -> hyper::Result<Response<Body>> {
        let (mut to_sign, info) = match SignRequest::from_req(&req) {
            Ok((a, b)) => (a, b),
            Err(_) => return Ok(bad_request()),
        };

        let secret = match self.secret_getter.get_secret(&info.id).await {
            Ok(a) => a,
            Err(e) => return Ok(internal_server(e)),
        };

        let Some(secret) = secret else {
            return Ok(bad_request());
        };

        let signer = UrlSigner::new(&info.id, &secret, self.self_host.clone());

        let Some(host) = to_sign.proxy_url.host() else {
            return Ok(bad_request())
        };
        let host = host.to_string();

        let proxy_url = match Uri::from_str(to_sign.proxy_url.as_str()) {
            Ok(a) => a,
            Err(_) => return Ok(bad_request()),
        };

        req.headers_mut().insert("host", host.parse().unwrap());
        *req.uri_mut() = proxy_url;

        if info.include_body {
            let content_length = match Self::parse_content_length(&req) {
                Ok(a) => a,
                Err(_) => return Ok(bad_request()),
            };
            let (parts, body) = req.into_parts();
            let body = match body_to_string(body, content_length).await {
                Ok(a) => a,
                Err(_) => return Ok(bad_request()),
            };
            to_sign.body = Some(body.clone());
            req = Request::from_parts(parts, string_to_body(&body))
        }

        let declared_signature = &info.signature;
        let actual_signature = match signer.get_signature(&to_sign) {
            Ok(a) => a,
            Err(e) => return Ok(internal_server(e)),
        };

        if declared_signature != &actual_signature {
            return Ok(bad_request());
        }

        let port = to_sign.proxy_url.port().unwrap_or(443);

        Self::proxy_request(&host, port, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_getter::InMemorySecretGetter;
    use hyper::HeaderMap;
    use lazy_static::lazy_static;
    use std::collections::HashMap;
    use time::{OffsetDateTime, PrimitiveDateTime};
    use url::Url;

    lazy_static! {
        static ref SERVER: Server<InMemorySecretGetter> =
            Server::<InMemorySecretGetter>::for_testing([("foo", "foo-secret")]);
        static ref HOST: Url = Url::parse("http://localhost:3000").unwrap();
    }

    #[tokio::test]
    async fn it_works() {
        tokio::task::spawn(SERVER.start());
        println!("{}", SERVER.self_host);
        let signer = UrlSigner::new("foo", "foo-secret", HOST.clone());

        let now = OffsetDateTime::now_utc();

        let sign_request = SignRequest {
            proxy_url: Url::parse("https://github.com").unwrap(),
            expiry: 10,
            datetime: PrimitiveDateTime::new(now.date(), now.time()),
            method: "POST".to_string(),
            headers: Some(
                HeaderMap::try_from(&HashMap::from([(
                    "host".to_string(),
                    "github.com".to_string(),
                )]))
                .unwrap(),
            ),
            queries: None,
            body: None,
        };

        let signed_url = signer.get_signed_url(&sign_request).unwrap();

        let response = reqwest::Client::new()
            .post(signed_url)
            .header("host", "github.com")
            .send()
            .await
            .unwrap();

        let status = response.status();
        let text = response.text().await.unwrap();
        println!("{text}");
        assert_eq!(status, StatusCode::OK);
    }
}
