FROM rust as builder

WORKDIR /app

COPY Cargo.toml .
COPY Cargo.lock .
COPY server ./server
COPY src ./src

RUN cargo install --path .

FROM debian:bullseye-slim

WORKDIR app

RUN apt update && apt install -y ca-certificates

COPY --from=builder /usr/local/cargo/bin/signway /usr/local/bin/signway

ENTRYPOINT ["signway"]
