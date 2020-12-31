FROM	debian:buster-slim
ARG	DEBIAN_FRONTEND=noninteractive
ENV 	RUSTUP_HOME=/usr/local/rustup \
	CARGO_HOME=/usr/local/cargo \
	PATH=/usr/local/cargo/bin:$PATH
RUN	apt-get update && apt-get install -y --no-install-recommends --no-install-suggests ca-certificates pkg-config libssl-dev gcc-multilib curl && \
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s \
	-- --default-toolchain nightly --profile minimal -y
COPY	common	/lumen/common
COPY	lumen	/lumen/lumen
COPY	Cargo.toml /lumen/
RUN	cd /lumen && cargo +nightly build --release

FROM	debian:buster-slim
ARG	DEBIAN_FRONTEND=noninteractive
RUN	apt-get update && apt-get install -y --no-install-recommends --no-install-suggests openssl netcat-openbsd 
COPY	--from=0	/lumen/target/release/lumen	/usr/bin/lumen
COPY	config-example.toml	docker-init.sh	/lumen/
WORKDIR	/lumen
