FROM debian:bullseye-slim

RUN apt update && apt install -y ca-certificates

ARG TARGET

COPY target/$TARGET/release/signway /usr/local/bin/signway

ENTRYPOINT ["signway"]
