// TCP echo server — demonstrates the high-level Server API.
//
// Two stacks (client + server) connected via virtual link.
// Uses tinytcp.init() for default 16-connection stack.

const std = @import("std");
const tinytcp = @import("tinytcp");

pub fn main() !void {
    var link_a = tinytcp.link.ChannelEndpoint.init();
    var link_b = tinytcp.link.ChannelEndpoint.init();

    var server_stack = tinytcp.init(&link_a, .{ 10, 0, 0, 1 });
    var client_stack = tinytcp.init(&link_b, .{ 10, 0, 0, 2 });

    // Server: listen
    var server = tinytcp.Server.init(&server_stack);
    if (!server.listen(80, 4)) return;

    // Client: connect
    var stream = tinytcp.Stream.connect(&client_stack, 0, .{ 10, 0, 0, 1 }, 80) orelse return;
    _ = client_stack.poll(0);

    // Pump packets until handshake completes
    var t: u64 = 2;
    while (t < 50) : (t += 1) {
        pump(&link_b, &server, t);
        pumpRaw(&link_a, &client_stack, t);
    }

    // Client sends
    _ = stream.send("hello tinytcp");
    _ = client_stack.poll(t);
    t += 1;

    // Pump data to server
    while (t < 100) : (t += 1) {
        pump(&link_b, &server, t);
        pumpRaw(&link_a, &client_stack, t);
    }
}

fn pump(src: *tinytcp.link.ChannelEndpoint, srv: anytype, now: u64) void {
    var buf: [1600]u8 = undefined;
    while (src.readOutbound(&buf)) |pkt| {
        handleEvent(srv.injectPacket(now, pkt));
    }
    handleEvent(srv.poll(now));
}

fn pumpRaw(src: *tinytcp.link.ChannelEndpoint, dst: anytype, now: u64) void {
    var buf: [1600]u8 = undefined;
    while (src.readOutbound(&buf)) |pkt| {
        _ = dst.injectPacket(now, pkt);
    }
    _ = dst.poll(now);
}

fn handleEvent(event: tinytcp.ServerEvent) void {
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
