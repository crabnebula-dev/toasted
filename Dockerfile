FROM rust:1.75-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
COPY src ./src
RUN touch src/main.rs && cargo build --release
RUN strip target/release/npm-compromise-scanner

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
RUN addgroup -g 1000 scanner && adduser -D -u 1000 -G scanner scanner
COPY --from=builder /usr/src/app/target/release/npm-compromise-scanner /usr/local/bin/
RUN chmod +x /usr/local/bin/npm-compromise-scanner
USER scanner
WORKDIR /scan
ENTRYPOINT ["npm-compromise-scanner"]
CMD ["."]
