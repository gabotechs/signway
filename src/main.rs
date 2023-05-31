use crate::secret_getter::InMemorySecretGetter;
use crate::server::Server;
use lazy_static::lazy_static;
use std::collections::HashMap;

#[cfg(test)]
mod _test_tools;
mod body;
mod route_gateway;
mod secret_getter;
mod server;
mod signing;

lazy_static! {
    static ref SERVER: Server<InMemorySecretGetter> =
        Server::from_env(InMemorySecretGetter(HashMap::new()))
            .expect("failure creating server from env");
}

#[tokio::main]
async fn main() {
    SERVER.start().await.expect("TODO: panic message");
}
