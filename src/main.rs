use std::collections::HashMap;

use crate::secret_getter::InMemorySecretGetter;
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
        "bar".to_string(),
    )])))
    .expect("failure creating server from env");
    server.start().await.expect("TODO: panic message");
}
