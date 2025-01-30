FROM alpine:3.20

VOLUME ["/aws_lc_rs"]

WORKDIR /

RUN apk add \
	alpine-sdk \
	bash \
	boost-dev \
	build-base \
	busybox-suid \
	clang-dev \
	cargo \
	curl \
	cmake \
	openssl-dev

ARG UID
RUN adduser -u $UID -S -s /bin/sh -G abuild satoshi
USER satoshi
WORKDIR /home/satoshi
ENV CARGO_HTTP_MULTIPLEXING=false

# If needed, setup Rust environment for user
#RUN cd "${HOME}" && \
#    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > ./rustup.sh && \
#    chmod +x ./rustup.sh && \
#    ./rustup.sh -y && \
#    . "${HOME}/.cargo/env" && \
#    echo '. "${HOME}/.cargo/env"' >> ${HOME}/.profile && \
#    cargo install --locked bindgen-cli && \
#    rustup component add rustfmt clippy && \
#    rm ./rustup.sh

COPY aws_lc_rs_build.sh /
COPY entry.sh /

ENTRYPOINT ["/entry.sh"]
