# syntax=docker/dockerfile:1
#
# Phantom Mirage I container image (based on Honeyd) (issue #20). Multi-arch: linux/amd64, linux/arm64.
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
 && strip /out/usr/bin/* /out/usr/lib/phantom-mirage/libphantom-mirage.so

########################################################################
# Runtime stage
FROM debian:13-slim

LABEL org.opencontainers.image.title="Phantom Mirage I" \
      org.opencontainers.image.description="Phantom Mirage I, based on Honeyd" \
      org.opencontainers.image.version="1.7.0" \
      org.opencontainers.image.licenses="GPL-2.0-or-later" \
      org.opencontainers.image.authors="Daniel de Jager <ddejager@dandejager.com>"

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libpcap0.8t64 libevent-2.1-7t64 libdumbnet1 zlib1g libedit2 \
 && rm -rf /var/lib/apt/lists/* /usr/share/doc /usr/share/man

COPY --from=build /out/ /
COPY docker/phantom-mirage.conf /etc/phantom-mirage/phantom-mirage.conf
COPY docker/entrypoint.sh /usr/local/bin/phantom-mirage-entrypoint

# phantom-mirage starts as root inside the container so it can open the capture
# interface, create /run/phantom-mirage (root-owned 0700, #14; control socket and pid
# file) and then drops to
# nobody by itself. Give the container only the capabilities listed in
# docs/docker.md (--cap-drop ALL; no --privileged).
ENV PHANTOM_MIRAGE_CONFIG=/etc/phantom-mirage/phantom-mirage.conf \
    PHANTOM_MIRAGE_INTERFACES=eth0

STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/phantom-mirage-entrypoint"]
