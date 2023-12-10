use std::fmt::Display;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use tracing::{error, info};

pub type SwBody = BoxBody<Bytes, hyper::Error>;

pub(crate) fn sw_body_from_string(str: String) -> SwBody {
    BoxBody::new(Full::new(str.into()).map_err(|err| match err {}))
}

pub(crate) async fn sw_body_to_string(
    mut body: SwBody,
    length: usize,
) -> Result<String, std::io::Error> {
    let mut data: Vec<u8> = vec![];
    while let Some(next) = body.frame().await {
        let frame = next.map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("Could not pull all frames from body: {err}"),
            )
        })?;
        if let Ok(frame) = frame.into_data() {
            data.append(&mut frame.to_vec())
        }
        if data.len() > length {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Body is longer than expected",
            ));
        }
    }

    String::from_utf8(data).map_err(|_e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Body could not be decoded as utf8",
        )
    })
}

pub(crate) fn monitor_sw_body<F: Fn(usize) + Sync + Send + 'static>(
    body: SwBody,
    on_data: F,
) -> SwBody {
    body.map_frame(move |frame| {
        frame.map_data(|data| {
            on_data(data.len());
            data
        })
    })
    .boxed()
}

pub(crate) fn full_response_into_sw_response(response: Response<Full<Bytes>>) -> Response<SwBody> {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, BoxBody::new(body.map_err(|err| match err {})))
}

pub(crate) fn incoming_body_into_sw_body(body: Incoming) -> SwBody {
    body.boxed()
}

pub(crate) fn incoming_request_into_sw_request(request: Request<Incoming>) -> Request<SwBody> {
    let (parts, body) = request.into_parts();
    Request::from_parts(parts, incoming_body_into_sw_body(body))
}

pub(crate) fn incoming_response_into_sw_response(response: Response<Incoming>) -> Response<SwBody> {
    let (parts, body) = response.into_parts();
    Response::from_parts(parts, incoming_body_into_sw_body(body))
}

pub fn empty() -> SwBody {
    BoxBody::default()
}

pub fn ok() -> Result<Response<SwBody>, hyper::Error> {
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty())
        .unwrap())
}

pub fn bad_request(e: impl Display) -> Result<Response<SwBody>, hyper::Error> {
    info!("Answering bad request: {e}");
    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(empty())
        .unwrap())
}

pub fn internal_server(e: impl Display) -> Result<Response<SwBody>, hyper::Error> {
    error!("Answering internal server error: {e}");
    Ok(Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .body(empty())
        .unwrap())
}

pub fn bad_gateway(e: impl Display) -> Result<Response<SwBody>, hyper::Error> {
    error!("Answering bad gateway: {e}");
    Ok(Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(empty())
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn converts_from_string_to_body_and_back() {
        let result = sw_body_to_string(sw_body_from_string("foo".to_string()), 3)
            .await
            .unwrap();
        assert_eq!(result, "foo")
    }

    #[tokio::test]
    async fn fails_to_read_long_body() {
        let err = sw_body_to_string(sw_body_from_string("foo".to_string()), 2)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "Body is longer than expected")
    }

    #[tokio::test]
    async fn works_with_a_really_long_body() {
        let len = 1e8 as usize;
        sw_body_to_string(sw_body_from_string("f".repeat(len)), len)
            .await
            .unwrap();
    }
}
