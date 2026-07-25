# TUN interop test environment
# Runs tinytcp stack on a TUN device and verifies communication with the host OS TCP/IP stack.
#
# Usage:
#   docker build -t tinytcp-tun-test tests/tun_interop/
#   docker run --cap-add=NET_ADMIN --device=/dev/net/tun tinytcp-tun-test
#
# What it does:
#   1. Creates a TUN device (tun0) with IP 10.99.0.1/24
#   2. Runs tinytcp as 10.99.0.2 on the other side of the TUN
#   3. Verifies: ping, TCP echo, UDP echo from Linux → tinytcp

FROM debian:bookworm-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iproute2 \
    iputils-ping \
    netcat-openbsd \
    ca-certificates \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Zig 0.15
ARG ZIG_VERSION=0.15.2
RUN arch=$(uname -m) && \
    if [ "$arch" = "x86_64" ]; then ZIG_ARCH="x86_64"; \
    elif [ "$arch" = "aarch64" ]; then ZIG_ARCH="aarch64"; \
    else echo "Unsupported arch: $arch" && exit 1; fi && \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${ZIG_ARCH}-${ZIG_VERSION}.tar.xz" \
      | tar -xJ -C /usr/local --strip-components=1

WORKDIR /app
COPY . /app/

# Build the TUN interop test binary
RUN zig build tun-test -Doptimize=ReleaseSafe

# Run
ENTRYPOINT ["/app/tests/tun_interop/run_test.sh"]
