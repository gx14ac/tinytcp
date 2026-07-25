// Stack: Central orchestrator for the TCP/IP stack.
//
// Sans-IO design: the stack itself performs no I/O.
// Caller is responsible for:
// 1. Injecting received packets (from wire)
// 2. Polling for outbound packets (to wire)
// 3. Driving timers
//
// The stack dispatches inbound IP packets to the appropriate transport endpoint
// via the demuxer, and queues outbound packets for extraction by the link layer.

const std = @import("std");
const header = @import("header.zig");
const packet_buf = @import("packet_buf.zig");
const PacketBuf = packet_buf.PacketBuf;
const checksum_mod = @import("checksum.zig");
const demux_mod = @import("demux.zig");
const link_mod = @import("link.zig");

/// Stack configuration.
pub const Config = struct {
    /// Maximum number of UDP endpoints.
    max_udp_endpoints: usize = 32,
    /// Local IPv4 addresses (max 4).
    local_ipv4: [4][4]u8 = .{.{ 0, 0, 0, 0 }} ** 4,
    local_ipv4_count: usize = 0,
};

/// Result of processing an inbound packet.
pub const InboundResult = union(enum) {
    /// Packet delivered to a UDP endpoint.
    delivered_udp: demux_mod.EndpointId,
    /// Packet delivered to a TCP endpoint.
    delivered_tcp: demux_mod.EndpointId,
    /// No matching endpoint found.
    no_endpoint,
    /// Packet had invalid header/checksum.
    invalid,
    /// Unsupported protocol.
    unsupported_protocol: u8,
};

/// The network stack.
pub const Stack = struct {
    const max_connected = 256;
    const max_listeners = 32;

    demuxer: demux_mod.Demuxer(max_connected, max_listeners),
    link: *link_mod.ChannelEndpoint,
    config: Config,

    /// UDP receive callback storage.
    /// When a UDP packet is delivered, it's stored here for the endpoint to read.
    udp_recv_bufs: [32][1500]u8 = undefined,
    udp_recv_lens: [32]u16 = [_]u16{0} ** 32,
    udp_recv_src_addrs: [32][4]u8 = undefined,
    udp_recv_src_ports: [32]u16 = [_]u16{0} ** 32,
    udp_recv_head: usize = 0,
    udp_recv_tail: usize = 0,
    udp_recv_count: usize = 0,
    /// Which endpoint ID each received UDP packet belongs to
    udp_recv_ep_ids: [32]demux_mod.EndpointId = [_]demux_mod.EndpointId{0} ** 32,

    pub fn init(link_ep: *link_mod.ChannelEndpoint, config: Config) Stack {
        return Stack{
            .demuxer = demux_mod.Demuxer(max_connected, max_listeners).init(),
            .link = link_ep,
            .config = config,
        };
    }

    /// Process one inbound packet from the link layer.
    /// Returns what happened with the packet.
    pub fn handleInbound(self: *Stack, raw_packet: []const u8) InboundResult {
        if (raw_packet.len < 1) return .invalid;

        const version = raw_packet[0] >> 4;
        return switch (version) {
            4 => self.handleIpv4(raw_packet),
            6 => self.handleIpv6(raw_packet),
            else => .invalid,
        };
    }

    fn handleIpv4(self: *Stack, raw_packet: []const u8) InboundResult {
        const ip_hdr = header.ipv4.Header.parse(raw_packet) catch return .invalid;

        // Verify IP header checksum
        if (!ip_hdr.isChecksumValid()) return .invalid;

        const proto = ip_hdr.protocol();
        const payload = ip_hdr.payload(raw_packet);

        switch (proto) {
            .udp => return self.handleUdp(ip_hdr.srcAddr(), ip_hdr.dstAddr(), payload),
            .tcp => return self.handleTcp(ip_hdr.srcAddr(), ip_hdr.dstAddr(), payload),
            else => return .{ .unsupported_protocol = @intFromEnum(proto) },
        }
    }

    fn handleIpv6(self: *Stack, raw_packet: []const u8) InboundResult {
        const ip_hdr = header.ipv6.Header.parse(raw_packet) catch return .invalid;

        const nh = ip_hdr.nextHeader();
        const payload = ip_hdr.payload(raw_packet);

        switch (nh) {
            .udp => {
                // For IPv6, we'd need 16-byte addresses; for now use zeroes
                return self.handleUdp(.{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, payload);
            },
            .tcp => {
                return self.handleTcp(.{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, payload);
            },
            else => return .{ .unsupported_protocol = @intFromEnum(nh) },
        }
    }

    fn handleUdp(self: *Stack, src_addr: [4]u8, dst_addr: [4]u8, udp_data: []const u8) InboundResult {
        const udp_hdr = header.udp.Header.parse(udp_data) catch return .invalid;

        // Build 4-tuple for demux lookup
        var tuple: demux_mod.FourTuple = .{
            .src_addr = [_]u8{0} ** 16,
            .dst_addr = [_]u8{0} ** 16,
            .src_port = udp_hdr.srcPort(),
            .dst_port = udp_hdr.dstPort(),
            .protocol = 17,
        };
        @memcpy(tuple.src_addr[12..16], &src_addr);
        @memcpy(tuple.dst_addr[12..16], &dst_addr);

        const ep_id = self.demuxer.lookup(tuple) orelse return .no_endpoint;

        // Store the UDP payload for the endpoint to read
        if (self.udp_recv_count < 32) {
            const payload = udp_hdr.payload(udp_data);
            if (payload.len <= 1500) {
                @memcpy(self.udp_recv_bufs[self.udp_recv_tail][0..payload.len], payload);
                self.udp_recv_lens[self.udp_recv_tail] = @intCast(payload.len);
                self.udp_recv_src_addrs[self.udp_recv_tail] = src_addr;
                self.udp_recv_src_ports[self.udp_recv_tail] = udp_hdr.srcPort();
                self.udp_recv_ep_ids[self.udp_recv_tail] = ep_id;
                self.udp_recv_tail = (self.udp_recv_tail + 1) % 32;
                self.udp_recv_count += 1;
            }
        }

        return .{ .delivered_udp = ep_id };
    }

    fn handleTcp(self: *Stack, src_addr: [4]u8, dst_addr: [4]u8, tcp_data: []const u8) InboundResult {
        const tcp_hdr = header.tcp.Header.parse(tcp_data) catch return .invalid;

        var tuple: demux_mod.FourTuple = .{
            .src_addr = [_]u8{0} ** 16,
            .dst_addr = [_]u8{0} ** 16,
            .src_port = tcp_hdr.srcPort(),
            .dst_port = tcp_hdr.dstPort(),
            .protocol = 6,
        };
        @memcpy(tuple.src_addr[12..16], &src_addr);
        @memcpy(tuple.dst_addr[12..16], &dst_addr);

        const ep_id = self.demuxer.lookup(tuple) orelse return .no_endpoint;
        return .{ .delivered_tcp = ep_id };
    }

    /// Bind a UDP listener on a given port. Returns the endpoint ID.
    pub fn bindUdp(self: *Stack, port: u16) ?demux_mod.EndpointId {
        const ep_id: demux_mod.EndpointId = @intCast(port); // Simple: use port as ID
        if (self.demuxer.registerListener(.{ .port = port, .protocol = 17 }, ep_id)) {
            return ep_id;
        }
        return null;
    }

    /// Unbind a UDP listener.
    pub fn unbindUdp(self: *Stack, port: u16) void {
        _ = self.demuxer.unregisterListener(.{ .port = port, .protocol = 17 });
    }

    /// Result of a UDP receive operation.
    pub const UdpRecvResult = struct {
        data: []const u8,
        src_addr: [4]u8,
        src_port: u16,
    };

    /// Read a received UDP datagram for a given endpoint.
    /// Returns (payload, src_addr, src_port) or null if none available.
    pub fn recvUdp(self: *Stack, ep_id: demux_mod.EndpointId) ?UdpRecvResult {
        // Scan receive queue for this endpoint
        var i: usize = 0;
        var idx = self.udp_recv_head;
        while (i < self.udp_recv_count) : (i += 1) {
            if (self.udp_recv_ep_ids[idx] == ep_id) {
                const data_len = self.udp_recv_lens[idx];
                const result = UdpRecvResult{
                    .data = self.udp_recv_bufs[idx][0..data_len],
                    .src_addr = self.udp_recv_src_addrs[idx],
                    .src_port = self.udp_recv_src_ports[idx],
                };
                // Remove from queue (mark as consumed by shifting head if at head)
                if (idx == self.udp_recv_head) {
                    self.udp_recv_head = (self.udp_recv_head + 1) % 32;
                    self.udp_recv_count -= 1;
                }
                return result;
            }
            idx = (idx + 1) % 32;
        }
        return null;
    }

    /// Send a UDP datagram. Builds IP+UDP headers and sends via link.
    pub fn sendUdp(self: *Stack, src_addr: [4]u8, src_port: u16, dst_addr: [4]u8, dst_port: u16, payload: []const u8) bool {
        // Build packet: IP header + UDP header + payload
        var buf: [1600]u8 = undefined;
        const ip_hlen = header.ipv4.min_header_len;
        const udp_hlen = header.udp.header_len;
        const total_len = ip_hlen + udp_hlen + payload.len;

        if (total_len > buf.len) return false;

        // Build IP header
        var ip_hdr = header.ipv4.MutableHeader.init(buf[0..ip_hlen]) catch return false;
        ip_hdr.setTotalLen(@intCast(total_len));
        ip_hdr.setTtl(64);
        ip_hdr.setProtocol(.udp);
        ip_hdr.setSrcAddr(src_addr);
        ip_hdr.setDstAddr(dst_addr);
        ip_hdr.setDontFragment();
        ip_hdr.computeChecksum();

        // Build UDP header
        var udp_hdr = header.udp.MutableHeader.init(buf[ip_hlen .. ip_hlen + udp_hlen]) catch return false;
        udp_hdr.setSrcPort(src_port);
        udp_hdr.setDstPort(dst_port);
        udp_hdr.setLength(@intCast(udp_hlen + payload.len));

        // Copy payload
        @memcpy(buf[ip_hlen + udp_hlen .. ip_hlen + udp_hlen + payload.len], payload);

        // Compute UDP checksum
        udp_hdr.computeChecksumIpv4(src_addr, dst_addr, buf[ip_hlen..total_len]);

        // Send via link
        var pb = PacketBuf.initWithData(&buf, 0, total_len);
        return self.link.extract(&pb);
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Stack: UDP echo flow" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = Stack.init(&link_ep, .{});

    // Bind UDP port 5000
    const ep_id = stack.bindUdp(5000) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(demux_mod.EndpointId, 5000), ep_id);

    // Craft an inbound UDP packet: src=10.0.0.1:1234 → dst=10.0.0.2:5000, payload="ping"
    var pkt: [48]u8 = undefined;
    // IP header
    var ip = header.ipv4.MutableHeader.init(pkt[0..20]) catch unreachable;
    ip.setTotalLen(32); // 20 + 8 + 4 = 32
    ip.setTtl(64);
    ip.setProtocol(.udp);
    ip.setSrcAddr(.{ 10, 0, 0, 1 });
    ip.setDstAddr(.{ 10, 0, 0, 2 });
    ip.computeChecksum();

    // UDP header
    var udp = header.udp.MutableHeader.init(pkt[20..28]) catch unreachable;
    udp.setSrcPort(1234);
    udp.setDstPort(5000);
    udp.setLength(12); // 8 + 4

    // Payload
    @memcpy(pkt[28..32], "ping");

    // UDP checksum
    udp.computeChecksumIpv4(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, pkt[20..32]);

    // Inject inbound
    const result = stack.handleInbound(pkt[0..32]);
    switch (result) {
        .delivered_udp => |id| try testing.expectEqual(ep_id, id),
        else => return error.TestUnexpectedResult,
    }

    // Read received datagram
    const recv = stack.recvUdp(ep_id) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "ping", recv.data);
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 1 }, &recv.src_addr);
    try testing.expectEqual(@as(u16, 1234), recv.src_port);

    // Send a reply
    try testing.expect(stack.sendUdp(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 1234, "pong"));
    try testing.expectEqual(@as(usize, 1), link_ep.outboundCount());
}

test "Stack: no endpoint returns no_endpoint" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = Stack.init(&link_ep, .{});

    // Craft packet to unbound port
    var pkt: [32]u8 = undefined;
    var ip = header.ipv4.MutableHeader.init(pkt[0..20]) catch unreachable;
    ip.setTotalLen(32);
    ip.setTtl(64);
    ip.setProtocol(.udp);
    ip.setSrcAddr(.{ 10, 0, 0, 1 });
    ip.setDstAddr(.{ 10, 0, 0, 2 });
    ip.computeChecksum();

    var udp = header.udp.MutableHeader.init(pkt[20..28]) catch unreachable;
    udp.setSrcPort(1234);
    udp.setDstPort(9999); // not bound
    udp.setLength(12);
    @memcpy(pkt[28..32], "test");
    udp.computeChecksumIpv4(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, pkt[20..32]);

    const result = stack.handleInbound(pkt[0..32]);
    try testing.expectEqual(InboundResult.no_endpoint, result);
}
