# Reproducible build + test on real Debian.
#
#   docker build -f test/Dockerfile --build-arg DEBIAN_RELEASE=trixie  \
#                --build-arg NGINX_VERSION=1.26.3 -t pgpauth:trixie .
#   docker run --rm pgpauth:trixie
#
#   docker build -f test/Dockerfile --build-arg DEBIAN_RELEASE=bookworm \
#                --build-arg NGINX_VERSION=1.22.1 -t pgpauth:bookworm .
#   docker run --rm pgpauth:bookworm
#
# A green run means: the module compiles cleanly on that Debian release and
# the full login flow + attack cases pass.

# Pinned by immutable digest, not by the mutable "${DEBIAN_RELEASE}-slim" tag.
# A digest cannot be interpolated from an ARG inside FROM, so both are declared
# as named stages and the requested one is selected by alias below.
#
# This ARG MUST stay above the first FROM: an ARG declared after one belongs to
# that build stage, so it would expand to nothing here and the final FROM would
# fail with "invalid reference format". Only a pre-FROM ARG is global.
ARG DEBIAN_RELEASE=trixie

FROM debian@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 AS base-trixie
FROM debian@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS base-bookworm

FROM base-${DEBIAN_RELEASE}

ARG NGINX_VERSION=1.26.3
ENV NGINX_VERSION=${NGINX_VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libc6-dev libssl-dev libpcre2-dev zlib1g-dev \
        gnupg curl ca-certificates redis-server \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /build

# Build with -Wall -Werror (nginx default); a warning fails the image build.
# The tarball is checked against the hash pinned in test/nginx-src.sha256 --
# TLS covers transit, not a compromised origin or a tampered release artifact.
RUN curl -fsSL -o "nginx-${NGINX_VERSION}.tar.gz" \
         "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
    && grep " nginx-${NGINX_VERSION}.tar.gz$" /src/test/nginx-src.sha256 \
       | sha256sum -c - \
    && tar xzf "nginx-${NGINX_VERSION}.tar.gz" \
    && cd "nginx-${NGINX_VERSION}" \
    && ./configure --with-compat --add-dynamic-module=/src \
                   --with-http_ssl_module --with-http_v2_module --with-threads \
                   --with-debug \
    && make -j"$(nproc)" \
    && cp objs/nginx /build/nginx \
    && cp objs/ngx_http_pgp_auth_module.so /build/module.so

CMD NGINX_BIN=/build/nginx MODULE_SO=/build/module.so sh /src/test/run-tests.sh
