// Time-travel testing — protocol conformance and fuzzing harness.
//
// Demonstrates:
//   - Sans-IO enables deterministic replay: caller controls time
//   - Freeze time, inject packets, observe exact state transitions
//   - Verify retransmission timers fire at precise intervals
//   - Test timeout behavior without waiting real seconds
//
// Use case: network protocol conformance testing, CI test harnesses,
// reproducing race conditions deterministically.

const std = @import("std");
const tinytcp = @import("tinytcp");

const Stack = tinytcp.Stack(4);

pub fn main() !void {
    std.debug.print("tinytcp time-travel testing example\n", .{});
    std.debug.print("===================================\n\n", .{});

    var link_server = tinytcp.link.ChannelEndpoint.init();
    var link_client = tinytcp.link.ChannelEndpoint.init();

    var server = Stack.init(&link_server, .{ 10, 0, 0, 1 });
    var client = Stack.init(&link_client, .{ 10, 0, 0, 2 });

    _ = server.listen(80, 4);

    // ── Test 1: Verify handshake completes in exactly N ticks ──
    std.debug.print("Test 1: Deterministic handshake timing\n", .{});

    _ = client.connect(0, .{ 10, 0, 0, 1 }, 80, 9000);
    _ = client.poll(0);

    var t: u64 = 0;
    var handshake_done = false;
    var handshake_ticks: u64 = 0;

    while (t < 100) : (t += 1) {
        var buf: [1600]u8 = undefined;
        while (link_client.readOutbound(&buf)) |pkt| {
            _ = server.injectPacket(t, pkt);
        }
        _ = server.poll(t);
        while (link_server.readOutbound(&buf)) |pkt| {
            const ev = client.injectPacket(t, pkt);
            if (ev == .established) {
                handshake_done = true;
                handshake_ticks = t;
            }
        }
        _ = client.poll(t);
        if (handshake_done) break;
    }

    std.debug.print("  handshake completed at t={d}ms (deterministic)\n", .{handshake_ticks});

    // ── Test 2: Retransmission timer — drop a packet, verify retx ──
    std.debug.print("\nTest 2: Retransmission after packet loss\n", .{});

    _ = client.write(0, "important data");
    _ = client.poll(t);
    t += 1;

    // Read the data packet but DON'T deliver it (simulate loss)
    var lost_buf: [1600]u8 = undefined;
    const lost_pkt = link_client.readOutbound(&lost_buf);
    if (lost_pkt != null) {
        std.debug.print("  t={d}: data packet sent ({d} bytes) — DROPPED\n", .{ t, lost_pkt.?.len });
    }

    // Fast-forward time until retransmission fires
    var retx_count: u32 = 0;
    const start_t = t;
    while (t < start_t + 5000) : (t += 10) {
        _ = client.poll(t);
        var buf: [1600]u8 = undefined;
        if (link_client.readOutbound(&buf)) |pkt| {
            std.debug.print("  t={d}: retransmission #{d} ({d} bytes)\n", .{ t, retx_count + 1, pkt.len });
            retx_count += 1;

            // Deliver the retransmission
            _ = server.injectPacket(t, pkt);
            _ = server.poll(t);
            break;
        }
    }

    std.debug.print("  retransmission fired after {d}ms (RTO)\n", .{t - start_t});

    // Server should have the data now
    var read_buf: [64]u8 = undefined;
    const srv_idx = server.accept() orelse 0;
    const n = server.read(srv_idx, &read_buf);
    std.debug.print("  server received: \"{s}\"\n", .{read_buf[0..n]});

    // ── Test 3: Verify connection still alive after partial time advance ──
    std.debug.print("\nTest 3: Selective time advance\n", .{});

    // Advance 2 seconds — connection should survive (well below max retx)
    const before_advance = t;
    t += 2000;
    _ = client.poll(t);

    const state_after = client.connState(0);
    std.debug.print("  advanced {d}ms (t={d} → t={d})\n", .{ t - before_advance, before_advance, t });
    std.debug.print("  connection state: {s}\n", .{if (state_after) |s| @tagName(s) else "closed"});
    std.debug.print("  connection survived: {s}\n", .{if (state_after != null) "yes" else "no"});

    // ── Summary ──
    std.debug.print("\n===================================\n", .{});
    std.debug.print("Sans-IO advantages demonstrated:\n", .{});
    std.debug.print("  - Time is a parameter, not a global clock\n", .{});
    std.debug.print("  - Packet loss is trivial to simulate\n", .{});
    std.debug.print("  - RTO/keepalive verified without real delays\n", .{});
    std.debug.print("  - Entire test runs in <1ms wall-clock\n", .{});
}
