FROM rust as builder

WORKDIR /app

COPY Cargo.toml .
COPY Cargo.lock .

COPY server/Cargo.toml server/Cargo.toml
RUN mkdir server/src && touch server/src/lib.rs
RUN mkdir src && echo "fn main() {}" > src/main.rs

RUN cargo build --release

COPY server ./server
COPY src ./src

RUN cargo install --path .

FROM debian:bullseye-slim

WORKDIR app

RUN apt update && apt install -y ca-certificates

COPY --from=builder /usr/local/cargo/bin/signway /usr/local/bin/signway

ENTRYPOINT ["signway"]
