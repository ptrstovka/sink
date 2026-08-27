# syntax=docker/dockerfile:1.7

FROM rust:1.92.0-alpine3.22 AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

ARG TARGETARCH
RUN --mount=type=cache,id=sink-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=sink-build-target-${TARGETARCH},target=/build/target \
    cargo build --release --locked --package sink-server --bin sink-server \
    && cp /build/target/release/sink-server /tmp/sink-server

FROM alpine:3.22

RUN addgroup -S -g 10001 sink \
    && adduser -S -D -H -u 10001 -G sink sink \
    && mkdir -p /data \
    && chown sink:sink /data

COPY --from=builder /tmp/sink-server /usr/local/bin/sink-server
COPY LICENSE-MIT LICENSE-APACHE /licenses/

ENV SINK_SERVER_LISTEN_ADDRESS=0.0.0.0:8080 \
    SINK_SERVER_SQLITE_PATH=/data/sink.sqlite3

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD wget -q -O - --header "Host: ${SINK_SERVER_PUBLIC_BASE_DOMAIN}" \
        http://127.0.0.1:8080/ | grep -qx sink

USER sink:sink
ENTRYPOINT ["sink-server"]
CMD ["serve"]
