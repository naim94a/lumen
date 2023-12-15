FROM rust:1.74.1-slim-buster
ARG	DEBIAN_FRONTEND=noninteractive
RUN	apt-get update && apt-get install -y --no-install-recommends --no-install-suggests ca-certificates pkg-config libssl-dev libpq-dev
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse

RUN --mount=type=cache,target=$CARGO_HOME/registry \
	cargo install diesel_cli --version 2.1.1 --no-default-features --features postgres

COPY	common	/lumen/common
COPY	lumen	/lumen/lumen
COPY	Cargo.toml /lumen/
RUN --mount=type=cache,target=$CARGO_HOME/registry,target=/lumen/target \
	cd /lumen && cargo build --release && cp /lumen/target/release/lumen /root/

FROM	debian:buster-slim
ARG	DEBIAN_FRONTEND=noninteractive
RUN	apt-get update && apt-get install -y --no-install-recommends --no-install-suggests openssl libpq5 && \
	sed -i -e 's,\[ v3_req \],\[ v3_req \]\nextendedKeyUsage = serverAuth,' /etc/ssl/openssl.cnf
RUN mkdir /usr/lib/lumen/

COPY 	--from=0	/usr/local/cargo/bin/diesel  /usr/bin/diesel
COPY 	--from=0	/lumen/common/migrations  /usr/lib/lumen/migrations
COPY 	--from=0	/lumen/common/diesel.toml  /usr/lib/lumen/
COPY	--from=0	/root/lumen	/usr/bin/lumen

COPY	config-example.toml	docker-init.sh	/lumen/
RUN	chmod a+x /lumen/docker-init.sh && chmod a+x /usr/bin/lumen
WORKDIR	/lumen
STOPSIGNAL SIGINT
CMD /lumen/docker-init.sh
