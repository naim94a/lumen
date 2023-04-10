FROM rust:1.68.2-slim-buster
ARG	DEBIAN_FRONTEND=noninteractive
RUN	apt-get update && apt-get install -y --no-install-recommends --no-install-suggests ca-certificates pkg-config libssl-dev libpq-dev
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN cargo install diesel_cli --version 2.0.1 --no-default-features --features postgres

COPY	common	/lumen/common
COPY	lumen	/lumen/lumen
COPY	Cargo.toml /lumen/
RUN	cd /lumen && cargo build --release

FROM	debian:buster-slim
ARG	DEBIAN_FRONTEND=noninteractive
RUN	apt-get update && apt-get install -y --no-install-recommends --no-install-suggests openssl libpq5 && \
	sed -i -e 's,\[ v3_req \],\[ v3_req \]\nextendedKeyUsage = serverAuth,' /etc/ssl/openssl.cnf 
RUN mkdir /usr/lib/lumen/

COPY 	--from=0	/usr/local/cargo/bin/diesel  /usr/bin/diesel
COPY 	--from=0	/lumen/common/migrations  /usr/lib/lumen/migrations
COPY 	--from=0	/lumen/common/diesel.toml  /usr/lib/lumen/
COPY	--from=0	/lumen/target/release/lumen	/usr/bin/lumen

COPY	config-example.toml	docker-init.sh	/lumen/
RUN	chmod a+x /lumen/docker-init.sh && chmod a+x /usr/bin/lumen
WORKDIR	/lumen
STOPSIGNAL SIGINT
ENTRYPOINT exec /lumen/docker-init.sh
