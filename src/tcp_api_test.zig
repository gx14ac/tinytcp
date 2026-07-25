// End-to-End tests for the high-level Tcp API (Listener + Stream).
//
// Validates that Tcp.Listener / Tcp.Stream work correctly over real
// packet exchange between two FullStack instances wired back-to-back.

const std = @import("std");
const testing = std.testing;
const link_mod = @import("link.zig");
const full_stack_mod = @import("full_stack.zig");
const tcp_mod = @import("tcp.zig");

const FullStack = full_stack_mod.FullStack(4);
const Tcp = tcp_mod.Tcp(FullStack);
const State = @import("transport/tcp/connection.zig").State;

const client_addr = [4]u8{ 10, 0, 0, 1 };
const server_addr = [4]u8{ 10, 0, 0, 2 };

fn pump(client: *FullStack, client_link: *link_mod.ChannelEndpoint, server: *FullStack, server_link: *link_mod.ChannelEndpoint, now_ms: *u64, max_rounds: usize) void {
    var rounds: usize = 0;
    while (rounds < max_rounds) : (rounds += 1) {
        deliver(client_link, server_link);
        deliver(server_link, client_link);
        injectAll(server, server_link, now_ms.*);
        injectAll(client, client_link, now_ms.*);
        _ = server.poll(now_ms.*);
        _ = client.poll(now_ms.*);
        now_ms.* += 1;
    }
}

fn deliver(src: *link_mod.ChannelEndpoint, dst: *link_mod.ChannelEndpoint) void {
    var buf: [1600]u8 = undefined;
    while (src.readOutbound(&buf)) |pkt| {
        _ = dst.writeInbound(pkt);
    }
}

fn injectAll(stack_inst: *FullStack, link: *link_mod.ChannelEndpoint, now_ms: u64) void {
    var buf: [1600]u8 = undefined;
    while (link.inject(&buf)) |pkt| {
        _ = stack_inst.injectPacket(now_ms, pkt);
    }
}

test "Tcp API: listen + connect + handshake" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    var listener = Tcp.Listener.init(&server, 80, 8) orelse return error.TestUnexpectedResult;
    var stream = Tcp.Stream.connect(&client, 0, server_addr, 80) orelse return error.TestUnexpectedResult;

    _ = client.poll(0);

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 30);

    try testing.expectEqual(State.established, stream.state().?);

    const accepted = listener.accept() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(State.established, accepted.state().?);
}

test "Tcp API: send and recv" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    var listener = Tcp.Listener.init(&server, 80, 8) orelse return error.TestUnexpectedResult;
    var stream = Tcp.Stream.connect(&client, 0, server_addr, 80) orelse return error.TestUnexpectedResult;
    _ = client.poll(0);

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 30);

    const msg = "hello tinytcp api";
    const written = stream.send(msg);
    try testing.expectEqual(msg.len, written);

    _ = client.poll(now);
    pump(&client, &client_link, &server, &server_link, &now, 20);

    const accepted = listener.accept() orelse return error.TestUnexpectedResult;

    var buf: [256]u8 = undefined;
    const n = accepted.recv(&buf);
    try testing.expect(n > 0);
    try testing.expectEqualSlices(u8, msg[0..n], buf[0..n]);
}

test "Tcp API: bidirectional echo" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    var listener = Tcp.Listener.init(&server, 7777, 8) orelse return error.TestUnexpectedResult;
    var stream = Tcp.Stream.connect(&client, 0, server_addr, 7777) orelse return error.TestUnexpectedResult;
    _ = client.poll(0);

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 30);

    // Client sends
    _ = stream.send("request");
    _ = client.poll(now);
    pump(&client, &client_link, &server, &server_link, &now, 20);

    // Server accepts, reads, echoes
    var srv_stream = listener.accept() orelse return error.TestUnexpectedResult;
    var buf: [256]u8 = undefined;
    const req_n = srv_stream.recv(&buf);
    try testing.expect(req_n > 0);
    try testing.expectEqualSlices(u8, "request"[0..req_n], buf[0..req_n]);

    _ = srv_stream.send(buf[0..req_n]);
    _ = server.poll(now);
    pump(&client, &client_link, &server, &server_link, &now, 20);

    // Client reads echo
    var resp_buf: [256]u8 = undefined;
    const resp_n = stream.recv(&resp_buf);
    try testing.expect(resp_n > 0);
    try testing.expectEqualSlices(u8, "request"[0..resp_n], resp_buf[0..resp_n]);
}

test "Tcp API: close" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    _ = Tcp.Listener.init(&server, 80, 8) orelse return error.TestUnexpectedResult;
    var stream = Tcp.Stream.connect(&client, 0, server_addr, 80) orelse return error.TestUnexpectedResult;
    _ = client.poll(0);

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 30);

    try testing.expectEqual(State.established, stream.state().?);

    stream.close();
    pump(&client, &client_link, &server, &server_link, &now, 60);

    const final = stream.state();
    if (final) |s| {
        try testing.expect(s == .time_wait or s == .closed or s == .fin_wait_1 or s == .fin_wait_2);
    }
}

test "Tcp API: large transfer via Stream" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    var listener = Tcp.Listener.init(&server, 80, 8) orelse return error.TestUnexpectedResult;
    var stream = Tcp.Stream.connect(&client, 0, server_addr, 80) orelse return error.TestUnexpectedResult;
    _ = client.poll(0);

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 30);

    var send_data: [4096]u8 = undefined;
    for (&send_data, 0..) |*b, i| {
        b.* = @intCast(i & 0xff);
    }

    // Send in chunks
    var total_sent: usize = 0;
    while (total_sent < send_data.len) {
        const n = stream.send(send_data[total_sent..]);
        if (n == 0) {
            pump(&client, &client_link, &server, &server_link, &now, 10);
            continue;
        }
        total_sent += n;
        pump(&client, &client_link, &server, &server_link, &now, 5);
    }

    pump(&client, &client_link, &server, &server_link, &now, 100);

    // Server accepts and reads
    const srv_stream = listener.accept() orelse return error.TestUnexpectedResult;
    var recv_data: [4096]u8 = undefined;
    var total_recv: usize = 0;
    var stall: usize = 0;
    while (total_recv < send_data.len and stall < 200) {
        const n = srv_stream.recv(recv_data[total_recv..]);
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

test "Tcp API: multiple streams" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    var listener = Tcp.Listener.init(&server, 80, 8) orelse return error.TestUnexpectedResult;

    var s0 = Tcp.Stream.connect(&client, 0, server_addr, 80) orelse return error.TestUnexpectedResult;
    var s1 = Tcp.Stream.connect(&client, 0, server_addr, 80) orelse return error.TestUnexpectedResult;
    _ = client.poll(0);

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 40);

    try testing.expectEqual(State.established, s0.state().?);
    try testing.expectEqual(State.established, s1.state().?);

    // Send different data on each stream
    _ = s0.send("stream-zero");
    _ = s1.send("stream-one");
    _ = client.poll(now);
    pump(&client, &client_link, &server, &server_link, &now, 20);

    // Accept both on server
    const a0 = listener.accept() orelse return error.TestUnexpectedResult;
    const a1 = listener.accept() orelse return error.TestUnexpectedResult;

    var buf0: [64]u8 = undefined;
    var buf1: [64]u8 = undefined;
    const n0 = a0.recv(&buf0);
    const n1 = a1.recv(&buf1);

    // Both streams should have received their respective data
    try testing.expect(n0 > 0);
    try testing.expect(n1 > 0);

    const got0 = buf0[0..n0];
    const got1 = buf1[0..n1];

    // Order depends on accept queue, so just check both messages arrived
    const has_zero = std.mem.eql(u8, got0, "stream-zero") or std.mem.eql(u8, got1, "stream-zero");
    const has_one = std.mem.eql(u8, got0, "stream-one") or std.mem.eql(u8, got1, "stream-one");
    try testing.expect(has_zero);
    try testing.expect(has_one);
}

// ==========================================================================
// Server API tests
// ==========================================================================

fn pumpWithServer(
    client: *FullStack,
    client_link: *link_mod.ChannelEndpoint,
    server: *FullStack,
    server_link: *link_mod.ChannelEndpoint,
    srv: *Tcp.Server,
    now_ms: *u64,
    max_rounds: usize,
    accepted: *[4]?Tcp.Stream,
    data_count: *usize,
) void {
    var rounds: usize = 0;
    while (rounds < max_rounds) : (rounds += 1) {
        deliver(client_link, server_link);
        deliver(server_link, client_link);

        // Inject into server and feed events to Server
        var buf: [1600]u8 = undefined;
        while (server_link.inject(&buf)) |pkt| {
            const event = server.injectPacket(now_ms.*, pkt);
            const se = srv.handle(event);
            handleServerEvent(se, accepted, data_count);
        }

        // Inject into client
        injectAll(client, client_link, now_ms.*);

        // Poll server
        const poll_event = server.poll(now_ms.*);
        const se = srv.handle(poll_event);
        handleServerEvent(se, accepted, data_count);

        _ = client.poll(now_ms.*);
        now_ms.* += 1;
    }
}

fn handleServerEvent(
    se: Tcp.ServerEvent,
    accepted: *[4]?Tcp.Stream,
    data_count: *usize,
) void {
    switch (se) {
        .accepted => |stream| {
            for (accepted) |*slot| {
                if (slot.* == null) {
                    slot.* = stream;
                    break;
                }
            }
        },
        .data => {
            data_count.* += 1;
        },
        .closed, .aborted, .none => {},
    }
}

test "Tcp Server API: accept via handle" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    var srv = Tcp.Server.init(&server);
    try testing.expect(srv.listen(80, 8));

    _ = Tcp.Stream.connect(&client, 0, server_addr, 80) orelse return error.TestUnexpectedResult;
    _ = client.poll(0);

    var accepted: [4]?Tcp.Stream = .{ null, null, null, null };
    var data_count: usize = 0;
    var now: u64 = 1;

    pumpWithServer(&client, &client_link, &server, &server_link, &srv, &now, 30, &accepted, &data_count);

    // Server should have accepted one connection
    try testing.expect(accepted[0] != null);
    try testing.expectEqual(State.established, accepted[0].?.state().?);
}

test "Tcp Server API: echo via handle" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    var srv = Tcp.Server.init(&server);
    try testing.expect(srv.listen(80, 8));

    var stream = Tcp.Stream.connect(&client, 0, server_addr, 80) orelse return error.TestUnexpectedResult;
    _ = client.poll(0);

    var accepted: [4]?Tcp.Stream = .{ null, null, null, null };
    var data_count: usize = 0;
    var now: u64 = 1;

    // Handshake
    pumpWithServer(&client, &client_link, &server, &server_link, &srv, &now, 30, &accepted, &data_count);

    // Client sends
    _ = stream.send("ping");
    _ = client.poll(now);

    // Pump and handle data event on server side
    pumpWithServer(&client, &client_link, &server, &server_link, &srv, &now, 20, &accepted, &data_count);

    try testing.expect(data_count > 0);

    // Read from accepted stream and echo back
    const srv_stream = accepted[0] orelse return error.TestUnexpectedResult;
    var buf: [64]u8 = undefined;
    const n = srv_stream.recv(&buf);
    try testing.expect(n > 0);
    try testing.expectEqualSlices(u8, "ping"[0..n], buf[0..n]);

    _ = srv_stream.send(buf[0..n]);
    _ = server.poll(now);

    // Pump response back to client
    pumpWithServer(&client, &client_link, &server, &server_link, &srv, &now, 20, &accepted, &data_count);

    var resp: [64]u8 = undefined;
    const resp_n = stream.recv(&resp);
    try testing.expect(resp_n > 0);
    try testing.expectEqualSlices(u8, "ping"[0..resp_n], resp[0..resp_n]);
}

test "Tcp Server API: connect outbound" {
    var client_link = link_mod.ChannelEndpoint.init();
    var server_link = link_mod.ChannelEndpoint.init();
    var client = FullStack.init(&client_link, client_addr);
    var server = FullStack.init(&server_link, server_addr);

    // "server" listens, "client" side uses Server.connect
    _ = server.listen(80, 8);

    var srv = Tcp.Server.init(&client);
    const stream = srv.connect(0, server_addr, 80) orelse return error.TestUnexpectedResult;
    _ = client.poll(0);

    var now: u64 = 1;
    pump(&client, &client_link, &server, &server_link, &now, 30);

    try testing.expectEqual(State.established, stream.state().?);
}
