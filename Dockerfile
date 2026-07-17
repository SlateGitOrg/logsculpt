# syntax=docker/dockerfile:1

# --- Build stage -----------------------------------------------------------
FROM rust:1.91-slim-bookworm AS builder
WORKDIR /build

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock* ./
RUN mkdir -p src benches \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && echo "fn main() {}" > benches/throughput.rs \
    && cargo build --release --bin logsculpt 2>/dev/null || true \
    && rm -rf src benches

COPY src ./src
COPY benches ./benches
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin logsculpt

# --- Runtime stage -----------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 10001 logsculpt
USER logsculpt
WORKDIR /home/logsculpt

COPY --from=builder /build/target/release/logsculpt /usr/local/bin/logsculpt

# Interactive TUI needs a real TTY (`docker run -it`); the non-interactive
# `--format json|csv` path works fine piped, e.g.:
#   docker run --rm -i logsculpt:latest - --format json < app.log
ENTRYPOINT ["logsculpt"]
CMD ["--help"]
