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

ARG DEBIAN_RELEASE=trixie
FROM debian:${DEBIAN_RELEASE}-slim

ARG NGINX_VERSION=1.26.3
ENV NGINX_VERSION=${NGINX_VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc make libc6-dev libssl-dev libpcre2-dev zlib1g-dev \
        gnupg curl ca-certificates redis-server \
    && rm -rf /var/lib/apt/lists/*

COPY . /src
WORKDIR /build

# Build with -Wall -Werror (nginx default); a warning fails the image build.
RUN curl -fsSL -o nginx.tgz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" \
    && tar xzf nginx.tgz \
    && cd "nginx-${NGINX_VERSION}" \
    && ./configure --with-compat --add-dynamic-module=/src \
                   --with-http_ssl_module --with-http_v2_module --with-threads \
                   --with-debug \
    && make -j"$(nproc)" \
    && cp objs/nginx /build/nginx \
    && cp objs/ngx_http_pgp_auth_module.so /build/module.so

CMD NGINX_BIN=/build/nginx MODULE_SO=/build/module.so sh /src/test/run-tests.sh
