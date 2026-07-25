// TCP echo server — demonstrates the high-level Server API.
//
// Two stacks (client + server) connected via virtual link.
// Server uses Stack.Server for zero-boilerplate event dispatch.

const std = @import("std");
const tinytcp = @import("tinytcp");

const Stack = tinytcp.Stack(4);

pub fn main() !void {
    var link_a = tinytcp.link.ChannelEndpoint.init();
    var link_b = tinytcp.link.ChannelEndpoint.init();

    var server_stack = Stack.init(&link_a, .{ 10, 0, 0, 1 });
    var client_stack = Stack.init(&link_b, .{ 10, 0, 0, 2 });

    // Server: listen
    var server = Stack.Server.init(&server_stack);
    if (!server.listen(80, 4)) return;

    // Client: connect
    var stream = Stack.Stream.connect(&client_stack, 0, .{ 10, 0, 0, 1 }, 80) orelse return;
    _ = client_stack.poll(0);

    // Pump packets until handshake completes, then send data
    var t: u64 = 2;
    while (t < 50) : (t += 1) {
        pumpToServer(&link_b, &server_stack, &server, t);
        pumpRaw(&link_a, &client_stack, t);
    }

    // Client sends
    _ = stream.send("hello tinytcp");
    _ = client_stack.poll(t);
    t += 1;

    // Pump data to server
    while (t < 100) : (t += 1) {
        pumpToServer(&link_b, &server_stack, &server, t);
        pumpRaw(&link_a, &client_stack, t);
    }
}

fn pumpToServer(src: *tinytcp.link.ChannelEndpoint, dst: *Stack, srv: *Stack.Server, now: u64) void {
    var buf: [1600]u8 = undefined;
    while (src.readOutbound(&buf)) |pkt| {
        const event = dst.injectPacket(now, pkt);
        handleEvent(srv.handle(event));
    }
    handleEvent(srv.handle(dst.poll(now)));
}

fn pumpRaw(src: *tinytcp.link.ChannelEndpoint, dst: *Stack, now: u64) void {
    var buf: [1600]u8 = undefined;
    while (src.readOutbound(&buf)) |pkt| {
        _ = dst.injectPacket(now, pkt);
    }
    _ = dst.poll(now);
}

fn handleEvent(event: Stack.ServerEvent) void {
    switch (event) {
        .accepted => {
            std.debug.print("server: accepted connection\n", .{});
        },
        .data => |s| {
            var buf: [4096]u8 = undefined;
            const n = s.recv(&buf);
            if (n > 0) {
                std.debug.print("server: echo \"{s}\"\n", .{buf[0..n]});
                _ = s.send(buf[0..n]);
            }
        },
        .closed => {
            std.debug.print("server: closed\n", .{});
        },
        .aborted, .none => {},
    }
}
