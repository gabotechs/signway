use std::fmt::Display;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Response, StatusCode};
use tracing::{error, info};

pub type SignwayResponseBody = BoxBody<Bytes, hyper::Error>;
pub type SignwayResponse = Response<SignwayResponseBody>;

pub(crate) fn from_string(str: String) -> SignwayResponseBody {
    BoxBody::new(Full::new(str.into()).map_err(|err| match err {}))
}

pub(crate) fn wrap_string(response: Response<String>) -> Response<SignwayResponseBody> {
    let (parts, body) = Response::into_parts(response);
    Response::from_parts(parts, from_string(body))
}

pub(crate) fn wrap_full(response: Response<Full<Bytes>>) -> Response<SignwayResponseBody> {
    let (parts, body) = Response::into_parts(response);
    Response::from_parts(parts, BoxBody::new(body.map_err(|err| match err {})))
}

pub(crate) fn wrap_incoming(response: Response<Incoming>) -> Response<SignwayResponseBody> {
    let (parts, body) = Response::into_parts(response);
    Response::from_parts(parts, BoxBody::new(body))
}

pub fn empty() -> SignwayResponseBody {
    BoxBody::default()
}

pub fn ok() -> Result<SignwayResponse, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty())
        .unwrap())
}

pub fn bad_request(e: impl Display) -> Result<SignwayResponse, hyper::Error> {
    info!("Answering bad request: {e}");
    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(empty())
        .unwrap())
}

pub fn internal_server(e: impl Display) -> Result<SignwayResponse, hyper::Error> {
    error!("Answering internal server error: {e}");
    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(empty())
        .unwrap())
}

pub fn bad_gateway(e: impl Display) -> Result<SignwayResponse, hyper::Error> {
    let err = format!("{e}");
    error!("Answering bad gateway: {err}");
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(empty())
        .unwrap())
}
