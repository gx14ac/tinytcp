// Packet filter / firewall — network appliance emulation.
//
// Demonstrates:
//   - Inspecting packets between two stacks (middlebox pattern)
//   - Drop/allow decisions based on port and protocol
//   - Logging dropped packets (IDS/IPS style)
//   - Sans-IO makes it trivial to insert a filter between any two endpoints
//
// Topology: client ←→ [filter] ←→ server
// Rule: only allow TCP port 80, drop everything else.

const std = @import("std");
const tinytcp = @import("tinytcp");

const ipv4_header = tinytcp.header.ipv4;
const tcp_header = tinytcp.header.tcp;

const Stack = tinytcp.Stack(4);

const FilterAction = enum { allow, drop };

const Rule = struct {
    proto: enum { tcp, udp, any },
    dst_port: ?u16,
    action: FilterAction,
};

const rules = [_]Rule{
    .{ .proto = .tcp, .dst_port = 80, .action = .allow },
    .{ .proto = .tcp, .dst_port = null, .action = .drop },
    .{ .proto = .udp, .dst_port = null, .action = .drop },
};

fn filterPacket(pkt: []const u8) FilterAction {
    const ip = ipv4_header.Header.parse(pkt) catch return .drop;
    const proto = ip.protocol();
    const payload = ip.payload(pkt);

    for (rules) |rule| {
        const proto_match = switch (rule.proto) {
            .tcp => proto == .tcp,
            .udp => proto == .udp,
            .any => true,
        };
        if (!proto_match) continue;

        if (rule.dst_port) |port| {
            const dst_port = switch (proto) {
                .tcp => blk: {
                    const tcp = tcp_header.Header.parse(payload) catch break :blk @as(?u16, null);
                    break :blk tcp.dstPort();
                },
                .udp => blk: {
                    if (payload.len < 4) break :blk @as(?u16, null);
                    break :blk std.mem.readInt(u16, payload[2..4], .big);
                },
                else => @as(?u16, null),
            };
            if (dst_port == null or dst_port.? != port) continue;
        }

        return rule.action;
    }
    return .allow;
}

pub fn main() !void {
    std.debug.print("tinytcp packet filter example\n", .{});
    std.debug.print("=============================\n", .{});
    std.debug.print("Rule: allow TCP:80, drop all other TCP/UDP\n\n", .{});

    var link_server = tinytcp.link.ChannelEndpoint.init();
    var link_client = tinytcp.link.ChannelEndpoint.init();

    var server_stack = Stack.init(&link_server, .{ 10, 0, 0, 1 });
    var client_stack = Stack.init(&link_client, .{ 10, 0, 0, 2 });

    _ = server_stack.listen(80, 4);
    _ = server_stack.listen(22, 4);

    // Client tries port 80 (allowed)
    const conn80 = client_stack.connect(0, .{ 10, 0, 0, 1 }, 80, 5000);
    _ = client_stack.poll(0);

    var t: u64 = 1;
    var allowed: u32 = 0;
    var dropped: u32 = 0;

    // Pump with filter in the middle
    while (t < 60) : (t += 1) {
        pumpFiltered(&link_client, &server_stack, t, &allowed, &dropped);
        pumpFiltered(&link_server, &client_stack, t, &allowed, &dropped);
    }

    std.debug.print("port 80 connection: {s}\n", .{if (conn80 != null) "established" else "failed"});

    // Client tries port 22 (blocked)
    _ = client_stack.connect(t, .{ 10, 0, 0, 1 }, 22, 5001);
    _ = client_stack.poll(t);
    t += 1;

    while (t < 120) : (t += 1) {
        pumpFiltered(&link_client, &server_stack, t, &allowed, &dropped);
        pumpFiltered(&link_server, &client_stack, t, &allowed, &dropped);
    }

    std.debug.print("\nFilter stats: {d} allowed, {d} dropped\n", .{ allowed, dropped });
}

fn pumpFiltered(src: *tinytcp.link.ChannelEndpoint, dst: *Stack, now: u64, allowed: *u32, dropped: *u32) void {
    var buf: [1600]u8 = undefined;
    while (src.readOutbound(&buf)) |pkt| {
        switch (filterPacket(pkt)) {
            .allow => {
                _ = dst.injectPacket(now, pkt);
                allowed.* += 1;
            },
            .drop => {
                const ip = ipv4_header.Header.parse(pkt) catch continue;
                const payload = ip.payload(pkt);
                const dst_port: u16 = if (ip.protocol() == .tcp)
                    (tcp_header.Header.parse(payload) catch continue).dstPort()
                else
                    0;
                std.debug.print("  [DROP] proto={s} dst_port={d}\n", .{ @tagName(ip.protocol()), dst_port });
                dropped.* += 1;
            },
        }
    }
    _ = dst.poll(now);
}
