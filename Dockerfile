FROM debian:bullseye-slim

RUN apt update && apt install -y ca-certificates

ARG TARGETPLATFORM
COPY target/$TARGETPLATFORM/release/signway /usr/local/bin/signway

ENTRYPOINT ["signway"]
