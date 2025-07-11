FROM rust:bookworm as builder
WORKDIR /usr/src/dns-rr
COPY . .
RUN cargo install --path .

FROM debian:bookworm-slim
# RUN apt-get update && apt-get install -y extra-runtime-dependencies && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/cargo/bin/dns-rr /usr/local/bin/dns-rr
CMD ["dns-rr"]