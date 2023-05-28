use std::net::SocketAddr;
use std::str::FromStr;
use std::u16;

use anyhow::Result;
use hyper::service::service_fn;
use hyper::Request;
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use crate::body::{body_to_string, string_to_body};
use crate::sign_request::SignRequest;
use crate::signer::Signer;

pub struct Server {
    port: u16,
    self_host: Url,
}

impl Server {
    pub fn from_env() -> Result<Server> {
        Ok(Server {
            port: u16::from_str(&std::env::var("PORT").unwrap_or("8765".to_string()))
                .expect("failed to parse PORT env variable"),
            self_host: Url::parse(
                &std::env::var("SELF_HOST").expect("SELF_HOST env variable not present"),
            )
            .expect("failed to parse SELF_HOST env variable"),
        })
    }

    pub fn new(port: u16, self_host: Url) -> Server {
        Server { port, self_host }
    }

    pub async fn start(&'static self) -> Result<()> {
        let in_addr: SocketAddr = ([0, 0, 0, 0], self.port).into();
        let listener = TcpListener::bind(in_addr).await?;

        loop {
            let (stream, _) = listener.accept().await?;
            let self_host = &self.self_host;

            let service = service_fn(move |mut req| async {
                let (mut to_sign, info) = SignRequest::from_req(&req).unwrap();
                let signer = Signer::new(&info.id, "", self_host.clone());

                if info.include_body {
                    let content_length = req.headers().get("content-length").unwrap();
                    let content_length = usize::from_str(content_length.to_str().unwrap()).unwrap();
                    let (parts, body) = req.into_parts();
                    let body = body_to_string(body, content_length).await.unwrap();
                    to_sign.body = Some(body.clone());
                    req = Request::from_parts(parts, string_to_body(&body))
                }

                let declared_signature = &info.signature;
                let actual_signature = &signer.get_signature(&to_sign).unwrap();

                if declared_signature != actual_signature {
                    panic!("signatures do not match");
                }

                let client_stream = TcpStream::connect("TODO").await.unwrap();

                let (mut sender, conn) = hyper::client::conn::handshake(client_stream).await?;
                tokio::task::spawn(async {
                    if let Err(err) = conn.await {
                        println!("Connection failed: {:?}", err);
                    }
                });

                sender.send_request(req).await
            });

            tokio::task::spawn(async move {
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
