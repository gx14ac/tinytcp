#!/bin/bash
# QEMU + TAP network interop test for tinytcp.
#
# Sets up a TAP device, launches QEMU with LAN9118 NIC, then tests
# ARP resolution, ICMP ping, and TCP echo.
#
# Requirements:
#   - Linux host with root access (for TAP setup)
#   - qemu-system-arm installed
#   - zig-out/bin/embedded-net binary (zig build embedded-net)
#
# Usage:
#   sudo ./tests/embedded/run_net_interop.sh

set -e

TAPDEV="tinytcp0"
HOST_IP="10.0.0.1"
GUEST_IP="10.0.0.2"
TCP_PORT=7777
KERNEL="zig-out/bin/embedded-net"
TIMEOUT=30

cleanup() {
    echo "[*] Cleaning up..."
    if [ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null; then
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    if ip link show "$TAPDEV" &>/dev/null; then
        ip link set "$TAPDEV" down 2>/dev/null || true
        ip tuntap del dev "$TAPDEV" mode tap 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "=== tinytcp QEMU + TAP Network Interop Test ==="
echo ""

# Check prerequisites
if [ ! -f "$KERNEL" ]; then
    echo "[!] Kernel binary not found: $KERNEL"
    echo "    Run: zig build embedded-net"
    exit 1
fi

if ! command -v qemu-system-arm &>/dev/null; then
    echo "[!] qemu-system-arm not found"
    exit 1
fi

# Step 1: Create TAP device
echo "[1/5] Creating TAP device: $TAPDEV"
ip tuntap add dev "$TAPDEV" mode tap
ip addr add "$HOST_IP/24" dev "$TAPDEV"
ip link set "$TAPDEV" up
# Disable checksum offload (bare-metal NIC cannot compute checksums)
ethtool -K "$TAPDEV" tx off rx off 2>/dev/null || true

# Step 2: Launch QEMU
echo "[2/5] Starting QEMU (mps2-an385 + LAN9118)"
qemu-system-arm \
    -machine mps2-an385 \
    -nographic \
    -semihosting \
    -nic tap,ifname="$TAPDEV",script=no,downscript=no,model=lan9118 \
    -kernel "$KERNEL" &
QEMU_PID=$!

# Wait for QEMU to boot (poll with ARP until reachable)
echo "    QEMU PID: $QEMU_PID"

# Step 3: Test ARP resolution (also serves as boot-readiness check)
echo "[3/5] Testing ARP resolution..."
PASS=0

ARP_OK=0
for i in $(seq 1 15); do
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "[!] QEMU exited unexpectedly"
        exit 1
    fi
    if arping -c 1 -w 1 -I "$TAPDEV" "$GUEST_IP" &>/dev/null; then
        ARP_OK=1
        break
    fi
    sleep 1
done

if [ "$ARP_OK" -eq 1 ]; then
    echo "    PASS: ARP resolution successful"
    PASS=$((PASS + 1))
else
    echo "    FAIL: ARP resolution failed (timeout after 15s)"
fi

# Step 4: Test ICMP ping
echo "[4/5] Testing ICMP ping..."
if ping -c 3 -W 5 "$GUEST_IP" &>/dev/null; then
    echo "    PASS: ICMP echo reply received"
    PASS=$((PASS + 1))
else
    echo "    FAIL: No ICMP echo reply"
fi

# Step 5: Test TCP echo
echo "[5/5] Testing TCP echo on port $TCP_PORT..."
sleep 1
RESPONSE=$(echo "hello tinytcp" | timeout 10 nc -w 5 "$GUEST_IP" "$TCP_PORT" 2>/dev/null || true)
if [ "$RESPONSE" = "hello tinytcp" ]; then
    echo "    PASS: TCP echo server working"
    PASS=$((PASS + 1))
else
    echo "    FAIL: TCP echo not received (got: '$RESPONSE')"
fi

# Summary
echo ""
echo "=== Results: $PASS/3 tests passed ==="

if [ "$PASS" -eq 3 ]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "SOME TESTS FAILED"
    exit 1
fi
