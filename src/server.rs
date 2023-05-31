use std::net::SocketAddr;
use std::str::FromStr;
use std::u16;

use anyhow::Result;
use hyper::service::service_fn;
use tokio::net::TcpListener;
use url::Url;

use crate::secret_getter::SecretGetter;

pub struct Server<T: SecretGetter> {
    pub port: u16,
    pub self_host: Url,
    pub secret_getter: T,
}

impl<T: SecretGetter> Server<T> {
    pub fn from_env(secret_getter: T) -> Result<Server<T>> {
        Ok(Server {
            port: u16::from_str(&std::env::var("PORT").unwrap_or("3000".to_string()))
                .expect("failed to parse PORT env variable"),
            self_host: Url::parse(
                &std::env::var("SELF_HOST").unwrap_or("http://localhost".to_string()),
            )
            .expect("failed to parse SELF_HOST env variable"),
            secret_getter,
        })
    }

    pub async fn start(&'static self) -> Result<()> {
        let in_addr: SocketAddr = ([0, 0, 0, 0], self.port).into();
        let listener = TcpListener::bind(in_addr).await?;

        println!("Server running in {}", in_addr);
        loop {
            let (stream, _) = listener.accept().await?;
            let service = service_fn(|req| self.route_gateway(req));

            tokio::spawn(async move {
                if let Err(err) = hyper::server::conn::Http::new()
                    .serve_connection(stream, service)
                    .await
                {
                    println!("Failed to serve the connection: {:?}", err);
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_getter::InMemorySecretGetter;
    use hyper::{HeaderMap, StatusCode};
    use lazy_static::lazy_static;
    use std::collections::HashMap;
    use std::thread::sleep;
    use std::time::Duration;
    use time::{OffsetDateTime, PrimitiveDateTime};
    use url::Url;

    use crate::signing::{SignRequest, UrlSigner};

    fn server_for_testing<const N: usize>(
        config: [(&str, &str); N],
    ) -> Server<InMemorySecretGetter> {
        Server {
            port: 3000,
            self_host: Url::parse("http://localhost:3000").unwrap(),
            secret_getter: InMemorySecretGetter(HashMap::from(
                config.map(|e| (e.0.to_string(), e.1.to_string())),
            )),
        }
    }

    lazy_static! {
        static ref SERVER: Server<InMemorySecretGetter> =
            server_for_testing([("foo", "foo-secret")]);
        static ref HOST: Url = {
            tokio::task::spawn(SERVER.start());
            sleep(Duration::from_millis(100));
            Url::parse("http://localhost:3000").unwrap()
        };
        static ref SIGNER: UrlSigner = UrlSigner::new("foo", "foo-secret", HOST.clone());
    }

    fn base_request() -> SignRequest {
        let now = OffsetDateTime::now_utc();

        SignRequest {
            proxy_url: Url::parse("https://postman-echo.com/get").unwrap(),
            expiry: 10,
            datetime: PrimitiveDateTime::new(now.date(), now.time()),
            method: "GET".to_string(),
            headers: Some(
                HeaderMap::try_from(&HashMap::from([(
                    "host".to_string(),
                    "localhost:3000".to_string(),
                )]))
                .unwrap(),
            ),
            body: None,
        }
    }

    #[tokio::test]
    async fn simple_get_works() {
        let signed_url = SIGNER.get_signed_url(&base_request()).unwrap();

        let response = reqwest::Client::new()
            .get(signed_url)
            .header("host", "localhost:3000")
            .send()
            .await
            .unwrap();

        let status = response.status();
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn signed_with_different_secret_does_not_work() {
        let bad_signer = UrlSigner::new("foo", "bad-secret", HOST.clone());

        let signed_url = bad_signer.get_signed_url(&base_request()).unwrap();

        let response = reqwest::Client::new()
            .get(signed_url)
            .header("host", "localhost:3000")
            .send()
            .await
            .unwrap();

        let status = response.status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
