FROM alpine:3.20

RUN apk add \
	alpine-sdk \
	bash \
	boost-dev \
	build-base \
	busybox-suid \
	clang-dev \
    curl \
	cmake \
	openssl-dev

ARG UID
RUN adduser -u $UID -S -s /bin/sh -G abuild satoshi
USER satoshi
WORKDIR /home/satoshi
ENV CARGO_HTTP_MULTIPLEXING=false

RUN cd "${HOME}" && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > ./rustup.sh && \
    chmod +x ./rustup.sh && \
    ./rustup.sh -y && \
    . "${HOME}/.cargo/env" && \
    echo '. "${HOME}/.cargo/env"' >> ${HOME}/.profile && \
    cargo install --locked bindgen-cli && \
    rustup component add rustfmt clippy && \
    rm ./rustup.sh
