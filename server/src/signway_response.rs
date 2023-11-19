use std::fmt::Display;

use bytes::Bytes;
use http_body_util::{Either, Full};
use hyper::body::Incoming;
use hyper::{Response, StatusCode};
use tracing::{error, info};

pub type SignwayResponse = Either<Full<Bytes>, Incoming>;

pub fn empty() -> SignwayResponse {
    SignwayResponse::Left(Full::default())
}

pub fn wrap_full(response: Response<Full<Bytes>>) -> Response<SignwayResponse> {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, SignwayResponse::Left(body))
}

pub fn wrap_incoming(response: Response<Incoming>) -> Response<SignwayResponse> {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, SignwayResponse::Right(body))
}

pub fn from_incoming(incoming: Incoming) -> SignwayResponse {
    SignwayResponse::Right(incoming)
}

pub fn from_full(full: Full<Bytes>) -> SignwayResponse {
    SignwayResponse::Left(full)
}

pub fn ok() -> Result<Response<SignwayResponse>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty())
        .unwrap())
}

pub fn bad_request(e: impl Display) -> Result<Response<SignwayResponse>, hyper::Error> {
    info!("Answering bad request: {e}");
    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(empty())
        .unwrap())
}

pub fn internal_server(e: impl Display) -> Result<Response<SignwayResponse>, hyper::Error> {
    error!("Answering internal server error: {e}");
    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(empty())
        .unwrap())
}

pub fn bad_gateway(e: impl Display) -> Result<Response<SignwayResponse>, hyper::Error> {
    let err = format!("{e}");
    error!("Answering bad gateway: {err}");
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(empty())
        .unwrap())
}
