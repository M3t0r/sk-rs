# Build stage
FROM rust:1.81.0-alpine as chef
WORKDIR /app
RUN apk add --no-cache alpine-sdk sqlite-libs
RUN cargo install cargo-chef

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release

# Runtime stage
FROM alpine:3.20

RUN addgroup -S app && adduser -S app -G app

RUN apk add --no-cache libgcc sqlite-libs

WORKDIR /app

COPY --from=builder /app/target/release/sk-rs /usr/bin
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

USER app

EXPOSE 3000

ENV RUST_BACKTRACE=full

LABEL org.opencontainers.image.authors="M3t0r <github@m3t0r.de>"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/M3t0r/sk-rs"

CMD ["sk-rs"]
