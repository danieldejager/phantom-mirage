# syntax=docker/dockerfile:1
#
# Honeyd container image (issue #20). Multi-arch: linux/amd64, linux/arm64.
# See docs/docker.md for the required capabilities and a macvlan example.

########################################################################
# Build stage
FROM debian:13-slim AS build

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential autoconf automake libtool bison flex pkg-config \
      libpcap-dev libevent-dev libdumbnet-dev zlib1g-dev libedit-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Plain `make install` (no Python needed since #36); headers and man pages
# are not needed at runtime.
RUN ./autogen.sh \
 && ./configure --prefix=/usr --sysconfdir=/etc \
 && make -j"$(nproc)" \
 && make install DESTDIR=/out \
 && rm -rf /out/usr/include /out/usr/share/man \
 && strip /out/usr/bin/* /out/usr/lib/honeyd/libhoneyd.so

########################################################################
# Runtime stage
FROM debian:13-slim

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libpcap0.8t64 libevent-2.1-7t64 libdumbnet1 zlib1g libedit2 \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

COPY --from=build /out/ /
COPY docker/honeyd.conf /etc/honeyd/honeyd.conf
COPY docker/entrypoint.sh /usr/local/bin/honeyd-entrypoint

# honeyd starts as root inside the container so it can open the capture
# interface, create /run/honeyd (root-owned 0700, #14) and then drops to
# nobody by itself. Give the container only the capabilities listed in
# docs/docker.md (--cap-drop ALL; no --privileged).
ENV HONEYD_CONFIG=/etc/honeyd/honeyd.conf \
    HONEYD_INTERFACES=eth0

STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/honeyd-entrypoint"]
