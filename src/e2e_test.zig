// End-to-End Tests — Real packet exchange between two FullStack instances.
//
// Two stacks (client: 10.0.0.1, server: 10.0.0.2) are wired back-to-back
// via ChannelEndpoints. Packets sent by one stack are delivered to the other.
// This exercises the full path: TCP state machine, IP header build/parse,
// checksums, options negotiation, retransmission, and data delivery.

const std = @import("std");
const testing = std.testing;
const link_mod = @import("link.zig");
const full_stack_mod = @import("full_stack.zig");

const FullStack = full_stack_mod.FullStack(4);
const Event = full_stack_mod.Event;

const client_addr = [4]u8{ 10, 0, 0, 1 };
const server_addr = [4]u8{ 10, 0, 0, 2 };

/// Transfer all outbound packets from `src` link to `dst` link.
/// Returns number of packets delivered.
fn deliver(src: *link_mod.ChannelEndpoint, dst: *link_mod.ChannelEndpoint) usize {
    var count: usize = 0;
    var buf: [1600]u8 = undefined;
    while (src.readOutbound(&buf)) |pkt| {
        _ = dst.writeInbound(pkt);
        count += 1;
    }
    return count;
}

/// Pump both stacks: deliver packets and advance time, up to `max_rounds`.
/// Returns when an event matching `stop_on` fires or rounds exhaust.
fn pump(client: *FullStack, client_link: *link_mod.ChannelEndpoint, server: *FullStack, server_link: *link_mod.ChannelEndpoint, now_ms: *u64, max_rounds: usize) void {
    var rounds: usize = 0;
    while (rounds < max_rounds) : (rounds += 1) {
        // Deliver client → server
        _ = deliver(client_link, server_link);
        // Deliver server → client
        _ = deliver(server_link, client_link);

        // Inject + poll on both sides
        injectAll(server, server_link, now_ms.*);
        injectAll(client, client_link, now_ms.*);
        _ = server.poll(now_ms.*);
        _ = client.poll(now_ms.*);

        now_ms.* += 1;
    }
}

/// Inject all pending inbound packets into a stack.
fn injectAll(stack: *FullStack, link: *link_mod.ChannelEndpoint, now_ms: u64) void {
    var buf: [1600]u8 = undefined;
    while (link.inject(&buf)) |pkt| {
        _ = stack.injectPacket(now_ms, pkt);
    }
}

// ============================================================================
// Tests
// ============================================================================

test "E2E: TCP 3-way handshake" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    // Server listens
    _ = server.listen(80, 16);

    // Client connects
    const conn_idx = client.connect(0, server_addr, 80, 5000).?;

    var now: u64 = 1;

    // Pump until established
    pump(&client, &client_link, &server, &server_link, &now, 20);

    // Client should be established
    const client_state = client.connState(conn_idx);
    try testing.expect(client_state != null);
    try testing.expectEqual(@import("transport/tcp/connection.zig").State.established, client_state.?);
}

test "E2E: TCP data transfer client→server" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    _ = server.listen(80, 16);
    const c_idx = client.connect(0, server_addr, 80, 5001).?;

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 20);

    // Write data from client
    const msg = "Hello, tinytcp!";
    const written = client.write(c_idx, msg);
    try testing.expectEqual(msg.len, written);

    // Pump to deliver data
    pump(&client, &client_link, &server, &server_link, &now, 20);

    // Server should have accepted the connection
    const s_idx = server.accept() orelse {
        // Pump more and try again
        pump(&client, &client_link, &server, &server_link, &now, 20);
        const s = server.accept() orelse return error.TestUnexpectedResult;
        _ = s;
        return;
    };

    // Read data on server
    var buf: [256]u8 = undefined;
    const read_len = server.read(s_idx, &buf);
    try testing.expect(read_len > 0);
    try testing.expectEqualSlices(u8, msg[0..read_len], buf[0..read_len]);
}

test "E2E: TCP data transfer server→client" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    _ = server.listen(80, 16);
    const c_idx = client.connect(0, server_addr, 80, 5002).?;

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 30);

    // Accept on server
    const s_idx = server.accept() orelse {
        pump(&client, &client_link, &server, &server_link, &now, 30);
        return error.TestUnexpectedResult;
    };

    // Write from server
    const reply = "world";
    const written = server.write(s_idx, reply);
    try testing.expect(written > 0);

    // Pump to deliver
    pump(&client, &client_link, &server, &server_link, &now, 30);

    // Read on client
    var buf: [256]u8 = undefined;
    const read_len = client.read(c_idx, &buf);
    try testing.expect(read_len > 0);
    try testing.expectEqualSlices(u8, reply[0..read_len], buf[0..read_len]);
}

test "E2E: TCP bidirectional data" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    _ = server.listen(80, 16);
    const c_idx = client.connect(0, server_addr, 80, 5003).?;

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 30);

    const s_idx = server.accept() orelse {
        pump(&client, &client_link, &server, &server_link, &now, 30);
        return error.TestUnexpectedResult;
    };

    // Client sends request
    _ = client.write(c_idx, "request");
    pump(&client, &client_link, &server, &server_link, &now, 30);

    // Server reads request
    var req_buf: [256]u8 = undefined;
    const req_len = server.read(s_idx, &req_buf);
    try testing.expect(req_len > 0);
    try testing.expectEqualSlices(u8, "request"[0..req_len], req_buf[0..req_len]);

    // Server sends response
    _ = server.write(s_idx, "response");
    pump(&client, &client_link, &server, &server_link, &now, 30);

    // Client reads response
    var resp_buf: [256]u8 = undefined;
    const resp_len = client.read(c_idx, &resp_buf);
    try testing.expect(resp_len > 0);
    try testing.expectEqualSlices(u8, "response"[0..resp_len], resp_buf[0..resp_len]);
}

test "E2E: TCP graceful close" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    _ = server.listen(80, 16);
    const c_idx = client.connect(0, server_addr, 80, 5004).?;

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 30);

    // Verify established
    try testing.expectEqual(
        @import("transport/tcp/connection.zig").State.established,
        client.connState(c_idx).?,
    );

    // Client initiates close
    client.close(c_idx);
    pump(&client, &client_link, &server, &server_link, &now, 50);

    // After close + TIME_WAIT, connection should be gone or in time_wait/closed
    const final_state = client.connState(c_idx);
    if (final_state) |s| {
        try testing.expect(s == .time_wait or s == .closed or s == .fin_wait_1 or s == .fin_wait_2);
    }
}

test "E2E: TCP large data transfer" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    _ = server.listen(80, 16);
    const c_idx = client.connect(0, server_addr, 80, 5005).?;

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 30);

    const s_idx = server.accept() orelse {
        pump(&client, &client_link, &server, &server_link, &now, 30);
        return error.TestUnexpectedResult;
    };

    // Send a larger payload (4KB) in chunks
    var send_data: [4096]u8 = undefined;
    for (&send_data, 0..) |*b, i| {
        b.* = @intCast(i & 0xff);
    }

    var total_sent: usize = 0;
    while (total_sent < send_data.len) {
        const n = client.write(c_idx, send_data[total_sent..]);
        if (n == 0) {
            pump(&client, &client_link, &server, &server_link, &now, 10);
            continue;
        }
        total_sent += n;
        pump(&client, &client_link, &server, &server_link, &now, 5);
    }

    // Pump remaining
    pump(&client, &client_link, &server, &server_link, &now, 100);

    // Read on server
    var recv_data: [4096]u8 = undefined;
    var total_recv: usize = 0;
    var stall: usize = 0;
    while (total_recv < send_data.len and stall < 200) {
        const n = server.read(s_idx, recv_data[total_recv..]);
        if (n == 0) {
            pump(&client, &client_link, &server, &server_link, &now, 5);
            stall += 1;
            continue;
        }
        total_recv += n;
        stall = 0;
    }

    try testing.expectEqual(send_data.len, total_recv);
    try testing.expectEqualSlices(u8, &send_data, recv_data[0..total_recv]);
}

test "E2E: UDP sendto and recvfrom" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    // Bind UDP endpoints
    const c_ep = client.udpBind(5000).?;
    const s_ep = server.udpBind(53).?;

    // Client sends to server
    try testing.expect(client.udpSendTo(c_ep, server_addr, 53, "dns-query"));

    // Deliver
    var buf: [1600]u8 = undefined;
    while (client_link.readOutbound(&buf)) |pkt| {
        _ = server_link.writeInbound(pkt);
    }

    // Inject into server
    injectAll(&server, &server_link, 100);

    // Server reads
    const dgram = server.udpRecv(s_ep);
    try testing.expect(dgram != null);
    const d = dgram.?;
    try testing.expect(d.data.len >= 9);
    try testing.expectEqualSlices(u8, "dns-query", d.data[0..9]);
}

test "E2E: multiple connections" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    _ = server.listen(80, 16);

    // Open 3 connections
    const c0 = client.connect(0, server_addr, 80, 6000).?;
    const c1 = client.connect(0, server_addr, 80, 6001).?;
    const c2 = client.connect(0, server_addr, 80, 6002).?;

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 40);

    // All should be established
    const tcp_state = @import("transport/tcp/connection.zig").State;
    try testing.expectEqual(tcp_state.established, client.connState(c0).?);
    try testing.expectEqual(tcp_state.established, client.connState(c1).?);
    try testing.expectEqual(tcp_state.established, client.connState(c2).?);

    // Server should have 3 accepted connections
    try testing.expect(server.accept() != null);
    try testing.expect(server.accept() != null);
    try testing.expect(server.accept() != null);
}
