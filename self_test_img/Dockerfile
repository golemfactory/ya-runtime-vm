FROM rust:1.70.0 as rust_builder
RUN rustup target add x86_64-unknown-linux-musl

FROM rust_builder as builder
WORKDIR /data
COPY . .
RUN cargo install --path . --target x86_64-unknown-linux-musl

FROM scratch
VOLUME [ "/mnt/out" ]
WORKDIR /
COPY --from=builder /usr/local/cargo/bin/ya-self-test /ya-self-test
CMD [ "/ya-self-test" ]
