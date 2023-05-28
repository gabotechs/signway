use crate::server::Server;
use lazy_static::lazy_static;

mod body;
mod server;
mod sign_request;
mod signer;
mod signing;

lazy_static! {
    static ref SERVER: Server = Server::from_env().expect("failure creating server from env");
}

#[tokio::main]
async fn main() {
    SERVER.start().await.expect("TODO: panic message");
}
