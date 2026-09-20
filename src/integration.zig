// Integration: demonstrates how to combine FullStack + Forwarder + DNS.
//
// This module shows the pattern for building a full userspace TCP/IP stack
// with NAT forwarding and split DNS, as used by a WireGuard tunnel endpoint.
//
// Architecture:
//   WireGuard ↔ LinkEndpoint ↔ Forwarder (NAT decisions) ↔ FullStack (TCP/IP)
//                                    ↕
//                            DNS Handler (split DNS)
//
// Sans-IO: the TunnelStack produces events and outbound packets;
// the caller handles OS sockets, DNS relay, and timer scheduling.

const std = @import("std");
const full_stack_mod = @import("full_stack.zig");
const forwarder_mod = @import("forward/forwarder.zig");
const flow_table_mod = @import("forward/flow_table.zig");
const dns_mod = @import("dns/handler.zig");
const link_mod = @import("link.zig");
const ipv4_header = @import("header/ipv4.zig");
const isn_mod = @import("isn.zig");

/// High-level event from the tunnel stack.
pub const TunnelEvent = union(enum) {
    /// A new TCP connection was accepted (caller should open OS socket).
    tcp_accepted: struct { conn_idx: u16, remote_addr: [4]u8, remote_port: u16 },
    /// TCP connection has data for the OS socket.
    tcp_data_ready: u16,
    /// TCP connection closed.
    tcp_closed: u16,
    /// A packet should be forwarded out (exit node mode).
    forward_packet: struct { data: []const u8 },
    /// DNS query needs resolution.
    dns_query: struct { id: u16 },
    /// Nothing happened.
    none,
};

/// Complete tunnel stack combining all layers.
pub fn TunnelStack(comptime max_conns: usize, comptime max_flows: usize) type {
    return struct {
        const Self = @This();
        const FS = full_stack_mod.FullStack(max_conns);

        tcp: FS,
        fwd: forwarder_mod.Forwarder(max_flows),
        link: *link_mod.ChannelEndpoint,

        pub fn init(link_ep: *link_mod.ChannelEndpoint, config: forwarder_mod.Config, secret: [16]u8) Self {
            return Self{
                .tcp = FS.initWithSecret(link_ep, config.local_addr, secret),
                .fwd = forwarder_mod.Forwarder(max_flows).init(config),
                .link = link_ep,
            };
        }

        /// Process an inbound packet from the WireGuard tunnel.
        pub fn handleInbound(self: *Self, now_ms: u64, raw: []const u8) TunnelEvent {
            if (raw.len < 20) return .none;

            const version = raw[0] >> 4;
            if (version == 6) {
                // IPv6: pass directly to TCP stack (no forwarder for v6 yet)
                const ev = self.tcp.injectPacket(now_ms, raw);
                return self.mapEvent(ev);
            }
            if (version != 4) return .none;

            // Parse IP to get 5-tuple for forwarding decision
            const ip_hdr = ipv4_header.Header.parse(raw) catch return .none;
            if (!ip_hdr.isChecksumValid()) return .none;

            const src_addr = ip_hdr.srcAddr();
            const dst_addr = ip_hdr.dstAddr();
            const proto_raw: u8 = @intFromEnum(ip_hdr.protocol());
            const ttl = ip_hdr.ttl();

            // Extract ports (TCP/UDP)
            var src_port: u16 = 0;
            var dst_port: u16 = 0;
            const payload = ip_hdr.payload(raw);
            if (payload.len >= 4 and (proto_raw == 6 or proto_raw == 17)) {
                src_port = std.mem.readInt(u16, payload[0..2], .big);
                dst_port = std.mem.readInt(u16, payload[2..4], .big);
            }

            const decision = self.fwd.decideInbound(now_ms, src_addr, src_port, dst_addr, dst_port, proto_raw, ttl);

            switch (decision) {
                .local => {
                    const ev = self.tcp.injectPacket(now_ms, raw);
                    return self.mapEvent(ev);
                },
                .forward => {
                    // Caller should send this packet out (exit node)
                    return .{ .forward_packet = .{ .data = raw } };
                },
                .drop => |reason| {
                    if (reason == .ttl_expired) {
                        self.sendIcmpTimeExceeded(raw, dst_addr, src_addr);
                    }
                    return .none;
                },
                .icmp_unreachable => return .none,
            }
        }

        /// Poll for outbound TCP packets and timer events.
        pub fn poll(self: *Self, now_ms: u64) TunnelEvent {
            const ev = self.tcp.poll(now_ms);
            return self.mapEvent(ev);
        }

        /// Write data to a TCP connection (from OS socket → tunnel).
        pub fn write(self: *Self, conn_idx: u16, data: []const u8) usize {
            return self.tcp.write(conn_idx, data);
        }

        /// Read data from a TCP connection (tunnel → OS socket).
        pub fn read(self: *Self, conn_idx: u16, buf: []u8) usize {
            return self.tcp.read(conn_idx, buf);
        }

        /// Close a TCP connection.
        pub fn close(self: *Self, conn_idx: u16) void {
            self.tcp.close(conn_idx);
        }

        /// Expire idle flows and timers.
        pub fn tick(self: *Self, now_ms: u64) void {
            _ = self.fwd.tick(now_ms);
            _ = self.tcp.poll(now_ms);
        }

        /// Send ICMP Time Exceeded (type 11, code 0) back to sender.
        fn sendIcmpTimeExceeded(self: *Self, offending_pkt: []const u8, our_addr: [4]u8, sender_addr: [4]u8) void {
            // ICMP Time Exceeded: IP hdr(20) + ICMP hdr(8) + first 28 bytes of offending packet
            const copy_len = @min(offending_pkt.len, 28);
            const icmp_payload_len: usize = 8 + copy_len;
            const total_len: usize = 20 + icmp_payload_len;

            var buf: [128]u8 = undefined;
            if (total_len > buf.len) return;

            // IP header
            var ip_mut = ipv4_header.MutableHeader.init(buf[0..20]) catch return;
            ip_mut.setTotalLen(@intCast(total_len));
            ip_mut.setTtl(64);
            ip_mut.setProtocol(.icmp);
            ip_mut.setSrcAddr(our_addr);
            ip_mut.setDstAddr(sender_addr);
            ip_mut.computeChecksum();

            // ICMP: type=11, code=0, checksum, unused(4 bytes)
            buf[20] = 11; // time exceeded
            buf[21] = 0; // code: TTL exceeded in transit
            buf[22] = 0; // checksum (will compute)
            buf[23] = 0;
            buf[24] = 0; // unused
            buf[25] = 0;
            buf[26] = 0;
            buf[27] = 0;
            // Copy first 28 bytes of offending IP packet
            @memcpy(buf[28 .. 28 + copy_len], offending_pkt[0..copy_len]);

            // Compute ICMP checksum
            const cksum_mod = @import("checksum.zig");
            buf[22] = 0;
            buf[23] = 0;
            const cksum = cksum_mod.compute(buf[20..total_len]);
            std.mem.writeInt(u16, buf[22..24], cksum, .big);

            // Send via link
            self.link.writeOutbound(buf[0..total_len]);
        }

        fn mapEvent(_: *Self, ev: full_stack_mod.Event) TunnelEvent {
            return switch (ev) {
                .accepted => |idx| .{
                    .tcp_accepted = .{
                        .conn_idx = idx,
                        .remote_addr = .{ 0, 0, 0, 0 }, // caller looks up via connId
                        .remote_port = 0,
                    },
                },
                .data_ready => |idx| .{ .tcp_data_ready = idx },
                .established => .none,
                .closed => |idx| .{ .tcp_closed = idx },
                .aborted => |idx| .{ .tcp_closed = idx },
                .udp_recv => .none,
                // Only ports registered with listenDeferred hold a SYN, and
                // this tunnel never registers one.
                .syn_pending => .none,
                .none => .none,
            };
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "TunnelStack: local packet goes to TCP stack" {
    var link_ep = link_mod.ChannelEndpoint.init();
    const config = forwarder_mod.Config{
        .local_addr = .{ 100, 64, 0, 1 },
        .exit_node = false,
    };
    var ts = TunnelStack(8, 64).init(&link_ep, config, .{0} ** 16);
    _ = ts.tcp.listen(80, 8);

    // Build a SYN to local_addr
    const full_stack_test = @import("full_stack.zig");
    var pkt_buf: [128]u8 = undefined;
    const syn_len = full_stack_test.buildTcpPacket(
        .{ 100, 64, 0, 2 },
        5000,
        .{ 100, 64, 0, 1 },
        80,
        1000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );

    const ev = ts.handleInbound(0, pkt_buf[0..syn_len]);
    switch (ev) {
        .tcp_accepted => {},
        else => return error.TestUnexpectedResult,
    }
}

test "TunnelStack: non-local drops when exit disabled" {
    var link_ep = link_mod.ChannelEndpoint.init();
    const config = forwarder_mod.Config{
        .local_addr = .{ 100, 64, 0, 1 },
        .exit_node = false,
    };
    var ts = TunnelStack(8, 64).init(&link_ep, config, .{0} ** 16);

    const full_stack_test = @import("full_stack.zig");
    var pkt_buf: [128]u8 = undefined;
    const data_len = full_stack_test.buildTcpPacket(
        .{ 100, 64, 0, 2 },
        5000,
        .{ 8, 8, 8, 8 }, // internet address (not local)
        443,
        1000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );

    const ev = ts.handleInbound(0, pkt_buf[0..data_len]);
    switch (ev) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
}

test "TunnelStack: exit node forwards" {
    var link_ep = link_mod.ChannelEndpoint.init();
    const config = forwarder_mod.Config{
        .local_addr = .{ 100, 64, 0, 1 },
        .exit_node = true,
    };
    var ts = TunnelStack(8, 64).init(&link_ep, config, .{0} ** 16);

    const full_stack_test = @import("full_stack.zig");
    var pkt_buf: [128]u8 = undefined;
    const data_len = full_stack_test.buildTcpPacket(
        .{ 100, 64, 0, 2 },
        5000,
        .{ 8, 8, 8, 8 },
        443,
        1000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );

    const ev = ts.handleInbound(0, pkt_buf[0..data_len]);
    switch (ev) {
        .forward_packet => {},
        else => return error.TestUnexpectedResult,
    }
}
