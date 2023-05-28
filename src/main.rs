mod signer;
mod signing;

use std::collections::HashMap;
use axum::{Json, Router};
use axum::http::StatusCode;
use axum::routing::{post};
use serde::{Deserialize, Serialize};

#[tokio::main]
async fn main() {
    let app: Router = Router::new()
        .route("/", post(root));

    let listener = tokio::net::TcpListener::bind("").await.unwrap();
}

#[derive(Deserialize)]
struct SignUrlRequest {
    method: String,
    url: String,
    secret_headers: HashMap<String, String>,
    headers: HashMap<String, String>,
    secret_params: HashMap<String, String>,
    params: HashMap<String, String>,
    body: String
}


#[derive(Serialize)]
struct SignUrlResponse {
    signed_url: String
}

async fn root(
    Json(payload): Json<SignUrlRequest>
) -> (StatusCode, Json<SignUrlResponse>) {
    (StatusCode::OK, Json(SignUrlResponse { signed_url: "".to_string()}))
}
