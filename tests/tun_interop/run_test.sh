#!/usr/bin/env bash
set -euo pipefail

# TUN interop test runner.
# Executed inside Docker container with NET_ADMIN + /dev/net/tun.
#
# Topology:
#   Linux kernel (10.99.0.1/24) ←→ tun0 ←→ tinytcp (10.99.0.2)

TINYTCP_IP="10.99.0.2"
TUN_IF="tun0"
HOST_IP="10.99.0.1"
RESULT=0

echo "═══════════════════════════════════════════════"
echo "  tinytcp TUN Interop Test (Linux)"
echo "═══════════════════════════════════════════════"
echo ""

# Start tinytcp TUN server in background
echo "[*] Starting tinytcp TUN server..."
/app/zig-out/bin/tun-test &
TINYTCP_PID=$!
sleep 1

# Verify process is alive
if ! kill -0 "$TINYTCP_PID" 2>/dev/null; then
    echo "[FAIL] tinytcp server failed to start"
    exit 1
fi

echo "[*] tinytcp running (PID=$TINYTCP_PID)"
echo ""

# --- Test 1: ICMP Ping ---
echo "─────────────────────────────────────────────"
echo "[TEST 1] ICMP Ping to $TINYTCP_IP"
if ping -c 3 -W 2 "$TINYTCP_IP" >/dev/null 2>&1; then
    echo "[PASS] Ping successful"
else
    echo "[FAIL] Ping failed"
    RESULT=1
fi
echo ""

# --- Test 2: TCP Echo ---
echo "─────────────────────────────────────────────"
echo "[TEST 2] TCP Echo (port 7777)"
ECHO_MSG="hello-tinytcp-$(date +%s)"
REPLY=$(echo "$ECHO_MSG" | nc -w 3 "$TINYTCP_IP" 7777 2>/dev/null || true)
if [ "$REPLY" = "$ECHO_MSG" ]; then
    echo "[PASS] TCP echo: sent='$ECHO_MSG', got='$REPLY'"
else
    echo "[FAIL] TCP echo: sent='$ECHO_MSG', got='$REPLY'"
    RESULT=1
fi
echo ""

# --- Test 3: TCP Large Payload ---
echo "─────────────────────────────────────────────"
echo "[TEST 3] TCP Large Payload (4KB)"
LARGE_DATA=$(dd if=/dev/urandom bs=4096 count=1 2>/dev/null | base64)
LARGE_REPLY=$(echo "$LARGE_DATA" | nc -w 5 "$TINYTCP_IP" 7777 2>/dev/null || true)
if [ "$LARGE_REPLY" = "$LARGE_DATA" ]; then
    echo "[PASS] TCP large payload echoed correctly"
else
    SENT_LEN=${#LARGE_DATA}
    RECV_LEN=${#LARGE_REPLY}
    echo "[FAIL] TCP large payload: sent $SENT_LEN bytes, got $RECV_LEN bytes"
    RESULT=1
fi
echo ""

# --- Test 4: UDP Echo ---
echo "─────────────────────────────────────────────"
echo "[TEST 4] UDP Echo (port 7778)"
UDP_MSG="udp-test-payload"
UDP_REPLY=$(echo "$UDP_MSG" | nc -u -w 2 "$TINYTCP_IP" 7778 2>/dev/null || true)
if [ "$UDP_REPLY" = "$UDP_MSG" ]; then
    echo "[PASS] UDP echo: sent='$UDP_MSG', got='$UDP_REPLY'"
else
    echo "[FAIL] UDP echo: sent='$UDP_MSG', got='$UDP_REPLY'"
    RESULT=1
fi
echo ""

# --- Test 5: Multiple TCP Connections ---
echo "─────────────────────────────────────────────"
echo "[TEST 5] Multiple concurrent TCP connections"
TMPDIR_CONC=$(mktemp -d)
for i in 1 2 3 4 5; do
    (
        MSG="conn-$i"
        R=$(echo "$MSG" | nc -w 3 "$TINYTCP_IP" 7777 2>/dev/null || true)
        if [ "$R" = "$MSG" ]; then
            echo "1" > "$TMPDIR_CONC/result_$i"
        else
            echo "0" > "$TMPDIR_CONC/result_$i"
        fi
    ) &
done
wait
PASS_COUNT=0
for i in 1 2 3 4 5; do
    if [ "$(cat "$TMPDIR_CONC/result_$i" 2>/dev/null)" = "1" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
    fi
done
rm -rf "$TMPDIR_CONC"
if [ "$PASS_COUNT" -eq 5 ]; then
    echo "[PASS] All 5 connections echoed correctly"
else
    echo "[FAIL] Only $PASS_COUNT/5 connections succeeded"
    RESULT=1
fi
echo ""

# Cleanup
kill "$TINYTCP_PID" 2>/dev/null || true
wait "$TINYTCP_PID" 2>/dev/null || true

echo "═══════════════════════════════════════════════"
if [ $RESULT -eq 0 ]; then
    echo "  ALL TESTS PASSED"
else
    echo "  SOME TESTS FAILED"
fi
echo "═══════════════════════════════════════════════"

exit $RESULT
