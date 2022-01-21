
# docker build -t lumen-builer -f build.Dockerfile .
# docker run --rm -v `pwd`/out:/out -it lumen-builder

FROM rust:latest
RUN apt -y update && apt install -y mingw-w64 zip jq
RUN rustup target add x86_64-pc-windows-gnu

COPY Cargo.toml /usr/src/lumen/Cargo.toml
COPY Cargo.lock /usr/src/lumen/Cargo.lock
COPY common /usr/src/lumen/common
COPY lumen /usr/src/lumen/lumen
WORKDIR /usr/src/lumen
RUN cargo fetch

RUN cargo build --release --target x86_64-unknown-linux-gnu && \
    cargo build --release --target x86_64-pc-windows-gnu

COPY README.md /usr/src/lumen/
COPY LICENSE /usr/src/lumen/
COPY config-example.toml /usr/src/lumen/

VOLUME [ "/out" ]
CMD mkdir /tmp/out/ && \
    cp README.md LICENSE config-example.toml /tmp/out/ && \
    cp target/x86_64-unknown-linux-gnu/release/lumen /tmp/out/ && \
    cp target/x86_64-pc-windows-gnu/release/lumen.exe /tmp/out/ && \
    cd /tmp/out/ && \
    tar czvf /out/lumen-x86_64-unknown-linux-gnu.tar.gz README.md LICENSE config-example.toml lumen && \
    zip -9 /out/lumen-x86_64-pc-windows-gnu.zip README.md LICENSE config-example.toml lumen.exe
