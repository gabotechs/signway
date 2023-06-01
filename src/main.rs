use std::collections::HashMap;
use hyper::HeaderMap;

use crate::secret_getter::{InMemorySecretGetter, SecretGetterResult};
use crate::server::Server;

#[cfg(test)]
mod _test_tools;
mod body;
mod route_gateway;
mod secret_getter;
mod server;
mod signing;

#[tokio::main]
async fn main() {
    let server = Server::from_env(InMemorySecretGetter(HashMap::from([(
        "foo".to_string(),
        SecretGetterResult {
            secret: "bar".to_string(),
            headers_extension: HeaderMap::new()
        },
    )])))
    .expect("failure creating server from env");
    server.start().await.expect("TODO: panic message");
}
