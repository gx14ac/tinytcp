// IP Forwarding — Layer 3 packet forwarding between interfaces.
//
// Sans-IO: evaluates forwarding decisions; caller performs actual packet I/O.
//
// Responsibilities:
// - Per-interface forwarding enable/disable
// - TTL decrement and IPv4 header checksum recompute
// - ICMP error generation (TTL exceeded, destination unreachable)
// - Route lookup for next hop (delegates to route.zig RouteTable)
// - Integration with packet_filter for FORWARD chain filtering

const std = @import("std");
const route_mod = @import("route.zig");
const packet_filter_mod = @import("packet_filter.zig");

/// Maximum number of interfaces (NICs) the forwarder manages.
const max_interfaces: usize = 8;

/// Interface configuration for forwarding.
pub const Interface = struct {
    active: bool = false,
    forwarding_enabled: bool = false,
    mtu: u16 = 1500,
    addr: [4]u8 = .{ 0, 0, 0, 0 },
};

/// Forwarding verdict.
pub const Verdict = enum {
    forward,
    drop,
    local,
    icmp_ttl_exceeded,
    icmp_dest_unreachable,
    icmp_need_fragment,
};

/// Forwarding result with next-hop info.
pub const ForwardResult = struct {
    verdict: Verdict = .drop,
    egress_iface: u8 = 0,
    next_hop: ?[4]u8 = null,
    new_ttl: u8 = 0,
    /// Egress MTU (set on icmp_need_fragment).
    mtu: u16 = 0,
};

/// ICMP error type constants.
pub const IcmpType = struct {
    pub const dest_unreachable: u8 = 3;
    pub const time_exceeded: u8 = 11;
};

/// ICMP code constants.
pub const IcmpCode = struct {
    pub const net_unreachable: u8 = 0;
    pub const host_unreachable: u8 = 1;
    pub const frag_needed: u8 = 4;
    pub const ttl_in_transit: u8 = 0;
};

/// IP Forwarder engine.
pub const IpForwarder = struct {
    interfaces: [max_interfaces]Interface = [_]Interface{.{}} ** max_interfaces,
    iface_count: usize = 0,
    routes: route_mod.RouteTable(64) = route_mod.RouteTable(64).init(),
    filter: ?*const packet_filter_mod.PacketFilter = null,
    /// Packets forwarded counter.
    forwarded_count: u64 = 0,
    /// Packets dropped counter.
    dropped_count: u64 = 0,

    pub fn init() IpForwarder {
        return .{};
    }

    /// Add an interface. Returns interface index or null if full.
    pub fn addInterface(self: *IpForwarder, addr: [4]u8, mtu: u16, forwarding: bool) ?u8 {
        if (self.iface_count >= max_interfaces) return null;
        for (&self.interfaces, 0..) |*iface, i| {
            if (!iface.active) {
                iface.* = .{
                    .active = true,
                    .forwarding_enabled = forwarding,
                    .mtu = mtu,
                    .addr = addr,
                };
                self.iface_count += 1;
                return @intCast(i);
            }
        }
        return null;
    }

    /// Enable/disable forwarding on an interface.
    pub fn setForwarding(self: *IpForwarder, iface_idx: u8, enabled: bool) void {
        if (iface_idx >= max_interfaces) return;
        if (self.interfaces[iface_idx].active) {
            self.interfaces[iface_idx].forwarding_enabled = enabled;
        }
    }

    /// Attach a packet filter for FORWARD chain.
    pub fn setFilter(self: *IpForwarder, filter: *const packet_filter_mod.PacketFilter) void {
        self.filter = filter;
    }

    /// Decide how to forward a packet.
    /// `ingress` is the interface index where the packet arrived.
    /// Returns the forwarding decision.
    pub fn forward(self: *IpForwarder, ingress: u8, src_addr: [4]u8, dst_addr: [4]u8, src_port: u16, dst_port: u16, protocol: packet_filter_mod.ProtoMatch, ttl: u8, pkt_len: u16) ForwardResult {
        // Check if ingress interface has forwarding enabled
        if (ingress >= max_interfaces or !self.interfaces[ingress].active) {
            self.dropped_count += 1;
            return .{ .verdict = .drop };
        }
        if (!self.interfaces[ingress].forwarding_enabled) {
            self.dropped_count += 1;
            return .{ .verdict = .drop };
        }

        // Is this packet for one of our interfaces?
        for (&self.interfaces) |*iface| {
            if (iface.active and std.mem.eql(u8, &iface.addr, &dst_addr)) {
                return .{ .verdict = .local };
            }
        }

        // TTL check
        if (ttl <= 1) {
            self.dropped_count += 1;
            return .{ .verdict = .icmp_ttl_exceeded };
        }

        // Route lookup
        const route = self.routes.lookupIpv4(dst_addr) orelse {
            self.dropped_count += 1;
            return .{ .verdict = .icmp_dest_unreachable };
        };

        const egress = route.nic_id;

        // Check egress interface
        if (egress >= max_interfaces or !self.interfaces[egress].active) {
            self.dropped_count += 1;
            return .{ .verdict = .icmp_dest_unreachable };
        }

        // MTU check
        if (pkt_len > self.interfaces[egress].mtu) {
            self.dropped_count += 1;
            return .{ .verdict = .icmp_need_fragment, .egress_iface = egress, .mtu = self.interfaces[egress].mtu };
        }

        // Packet filter (FORWARD chain)
        if (self.filter) |pf| {
            const pkt_info = packet_filter_mod.PacketInfo{
                .src_addr = src_addr,
                .dst_addr = dst_addr,
                .src_port = src_port,
                .dst_port = dst_port,
                .protocol = protocol,
                .direction = .both, // FORWARD chain
            };
            if (pf.evaluate(pkt_info) == .deny) {
                self.dropped_count += 1;
                return .{ .verdict = .drop };
            }
        }

        // Determine next hop
        const next_hop: ?[4]u8 = if (route.gateway) |gw| gw[0..4].* else null;

        self.forwarded_count += 1;
        return .{
            .verdict = .forward,
            .egress_iface = egress,
            .next_hop = next_hop,
            .new_ttl = ttl - 1,
        };
    }

    /// Decrement TTL and recompute IPv4 header checksum (in-place).
    /// `header` must be a mutable slice of at least 20 bytes (IPv4 header).
    /// Returns false if TTL would reach 0.
    pub fn decrementTtl(header: []u8) bool {
        if (header.len < 20) return false;
        const ttl = header[8];
        if (ttl <= 1) return false;
        header[8] = ttl - 1;

        // Full recompute of IPv4 header checksum.
        header[10] = 0;
        header[11] = 0;
        const ihl: usize = @as(usize, header[0] & 0x0F) * 4;
        const hdr_len = @min(ihl, header.len);
        var cksum: u32 = 0;
        var i: usize = 0;
        while (i + 1 < hdr_len) : (i += 2) {
            cksum += @as(u32, header[i]) << 8 | @as(u32, header[i + 1]);
        }
        while (cksum >> 16 != 0) {
            cksum = (cksum & 0xffff) + (cksum >> 16);
        }
        const result = ~@as(u16, @intCast(cksum & 0xffff));
        header[10] = @intCast(result >> 8);
        header[11] = @intCast(result & 0xff);
        return true;
    }

    /// Build an ICMP Time Exceeded message.
    /// Returns bytes written to `out`. Includes IP header of the error packet.
    /// `original_ip` is the first 28+ bytes of the offending packet (IP header + 8 bytes).
    pub fn buildIcmpTimeExceeded(src_addr: [4]u8, dst_addr: [4]u8, original_ip: []const u8, out: []u8) usize {
        return buildIcmpError(IcmpType.time_exceeded, IcmpCode.ttl_in_transit, 0, src_addr, dst_addr, original_ip, out);
    }

    /// Build an ICMP Destination Unreachable message.
    pub fn buildIcmpDestUnreachable(src_addr: [4]u8, dst_addr: [4]u8, code: u8, original_ip: []const u8, out: []u8) usize {
        return buildIcmpError(IcmpType.dest_unreachable, code, 0, src_addr, dst_addr, original_ip, out);
    }

    /// Build an ICMP Fragmentation Needed (Type 3, Code 4) with Next-Hop MTU (RFC 1191).
    pub fn buildIcmpNeedFragment(src_addr: [4]u8, dst_addr: [4]u8, next_hop_mtu: u16, original_ip: []const u8, out: []u8) usize {
        return buildIcmpError(IcmpType.dest_unreachable, IcmpCode.frag_needed, next_hop_mtu, src_addr, dst_addr, original_ip, out);
    }

    /// Build a generic ICMP error message (IP header + ICMP header + original data).
    /// `extra` is placed in ICMP header bytes 6-7 (used as Next-Hop MTU for frag_needed).
    fn buildIcmpError(icmp_type: u8, icmp_code: u8, extra: u16, src_addr: [4]u8, dst_addr: [4]u8, original_ip: []const u8, out: []u8) usize {
        // ICMP error: IP(20) + ICMP(8) + original IP header + 8 bytes
        const max_include: usize = 28;
        const include_len: usize = if (original_ip.len < max_include) original_ip.len else max_include;
        const icmp_len: usize = 8 + include_len;
        const total: usize = 20 + icmp_len;

        if (out.len < total) return 0;

        // IP header
        out[0] = 0x45; // version=4, IHL=5
        out[1] = 0; // DSCP/ECN
        out[2] = @intCast(total >> 8);
        out[3] = @intCast(total & 0xff);
        out[4] = 0; // identification
        out[5] = 0;
        out[6] = 0x40; // DF
        out[7] = 0;
        out[8] = 64; // TTL
        out[9] = 1; // protocol = ICMP
        out[10] = 0; // checksum (computed below)
        out[11] = 0;
        @memcpy(out[12..16], &src_addr);
        @memcpy(out[16..20], &dst_addr);

        // IP checksum
        var ip_cksum: u32 = 0;
        var i: usize = 0;
        while (i < 20) : (i += 2) {
            ip_cksum += @as(u32, out[i]) << 8 | @as(u32, out[i + 1]);
        }
        while (ip_cksum >> 16 != 0) {
            ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
        }
        const ip_sum = ~@as(u16, @intCast(ip_cksum & 0xffff));
        out[10] = @intCast(ip_sum >> 8);
        out[11] = @intCast(ip_sum & 0xff);

        // ICMP header
        out[20] = icmp_type;
        out[21] = icmp_code;
        out[22] = 0; // checksum
        out[23] = 0;
        out[24] = 0; // unused
        out[25] = 0;
        // Bytes 6-7: Next-Hop MTU (RFC 1191, used for Type 3 Code 4)
        out[26] = @intCast(extra >> 8);
        out[27] = @intCast(extra & 0xff);

        // Original IP packet (header + first 8 bytes of payload)
        @memcpy(out[28 .. 28 + include_len], original_ip[0..include_len]);

        // ICMP checksum
        var icmp_cksum: u32 = 0;
        var j: usize = 20;
        while (j + 1 < total) : (j += 2) {
            icmp_cksum += @as(u32, out[j]) << 8 | @as(u32, out[j + 1]);
        }
        if (j < total) {
            icmp_cksum += @as(u32, out[j]) << 8;
        }
        while (icmp_cksum >> 16 != 0) {
            icmp_cksum = (icmp_cksum & 0xffff) + (icmp_cksum >> 16);
        }
        const icmp_sum = ~@as(u16, @intCast(icmp_cksum & 0xffff));
        out[22] = @intCast(icmp_sum >> 8);
        out[23] = @intCast(icmp_sum & 0xff);

        return total;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "IpForwarder: basic forward" {
    var fwd = IpForwarder.init();
    // Interface 0: ingress (10.0.0.0/24)
    const if0 = fwd.addInterface(.{ 10, 0, 0, 1 }, 1500, true).?;
    // Interface 1: egress (192.168.1.0/24)
    const if1 = fwd.addInterface(.{ 192, 168, 1, 1 }, 1500, true).?;

    // Route: 192.168.1.0/24 via if1
    try testing.expect(fwd.routes.addRoute(route_mod.Prefix.fromIpv4(.{ 192, 168, 1, 0 }, 24), null, 0, if1));

    const result = fwd.forward(if0, .{ 10, 0, 0, 2 }, .{ 192, 168, 1, 100 }, 5000, 80, .tcp, 64, 100);
    try testing.expectEqual(Verdict.forward, result.verdict);
    try testing.expectEqual(if1, result.egress_iface);
    try testing.expectEqual(@as(u8, 63), result.new_ttl);
}

test "IpForwarder: local delivery" {
    var fwd = IpForwarder.init();
    _ = fwd.addInterface(.{ 10, 0, 0, 1 }, 1500, true);

    const result = fwd.forward(0, .{ 10, 0, 0, 2 }, .{ 10, 0, 0, 1 }, 5000, 80, .tcp, 64, 100);
    try testing.expectEqual(Verdict.local, result.verdict);
}

test "IpForwarder: TTL expired" {
    var fwd = IpForwarder.init();
    _ = fwd.addInterface(.{ 10, 0, 0, 1 }, 1500, true);
    try testing.expect(fwd.routes.addRoute(route_mod.Prefix.fromIpv4(.{ 192, 168, 1, 0 }, 24), null, 0, 0));

    const result = fwd.forward(0, .{ 10, 0, 0, 2 }, .{ 192, 168, 1, 1 }, 5000, 80, .tcp, 1, 100);
    try testing.expectEqual(Verdict.icmp_ttl_exceeded, result.verdict);
}

test "IpForwarder: no route" {
    var fwd = IpForwarder.init();
    _ = fwd.addInterface(.{ 10, 0, 0, 1 }, 1500, true);

    const result = fwd.forward(0, .{ 10, 0, 0, 2 }, .{ 172, 16, 0, 1 }, 5000, 80, .tcp, 64, 100);
    try testing.expectEqual(Verdict.icmp_dest_unreachable, result.verdict);
}

test "IpForwarder: forwarding disabled" {
    var fwd = IpForwarder.init();
    _ = fwd.addInterface(.{ 10, 0, 0, 1 }, 1500, false); // forwarding OFF
    try testing.expect(fwd.routes.addRoute(route_mod.Prefix.fromIpv4(.{ 192, 168, 1, 0 }, 24), null, 0, 0));

    const result = fwd.forward(0, .{ 10, 0, 0, 2 }, .{ 192, 168, 1, 100 }, 5000, 80, .tcp, 64, 100);
    try testing.expectEqual(Verdict.drop, result.verdict);
}

test "IpForwarder: packet filter denies" {
    var fwd = IpForwarder.init();
    const if0 = fwd.addInterface(.{ 10, 0, 0, 1 }, 1500, true).?;
    const if1 = fwd.addInterface(.{ 192, 168, 1, 1 }, 1500, true).?;
    try testing.expect(fwd.routes.addRoute(route_mod.Prefix.fromIpv4(.{ 192, 168, 1, 0 }, 24), null, 0, if1));

    // Block all forwarded TCP
    var pf = packet_filter_mod.PacketFilter.init();
    try testing.expect(pf.addRule(.{
        .action = .deny,
        .direction = .both,
        .protocol = .tcp,
    }));
    fwd.setFilter(&pf);

    const result = fwd.forward(if0, .{ 10, 0, 0, 2 }, .{ 192, 168, 1, 100 }, 5000, 80, .tcp, 64, 100);
    try testing.expectEqual(Verdict.drop, result.verdict);
}

test "IpForwarder: MTU exceeded" {
    var fwd = IpForwarder.init();
    _ = fwd.addInterface(.{ 10, 0, 0, 1 }, 1500, true);
    const if1 = fwd.addInterface(.{ 192, 168, 1, 1 }, 576, true).?; // small MTU
    try testing.expect(fwd.routes.addRoute(route_mod.Prefix.fromIpv4(.{ 192, 168, 1, 0 }, 24), null, 0, if1));

    const result = fwd.forward(0, .{ 10, 0, 0, 2 }, .{ 192, 168, 1, 100 }, 5000, 80, .tcp, 64, 1400);
    try testing.expectEqual(Verdict.icmp_need_fragment, result.verdict);
    try testing.expectEqual(@as(u16, 576), result.mtu);
}

test "IpForwarder: next hop via gateway" {
    var fwd = IpForwarder.init();
    _ = fwd.addInterface(.{ 10, 0, 0, 1 }, 1500, true);
    const if1 = fwd.addInterface(.{ 192, 168, 1, 1 }, 1500, true).?;

    // Route with gateway
    var gw: [16]u8 = .{0} ** 16;
    gw[0] = 192;
    gw[1] = 168;
    gw[2] = 1;
    gw[3] = 254;
    try testing.expect(fwd.routes.addRoute(route_mod.Prefix.fromIpv4(.{ 0, 0, 0, 0 }, 0), gw, 100, if1));

    const result = fwd.forward(0, .{ 10, 0, 0, 2 }, .{ 8, 8, 8, 8 }, 5000, 53, .udp, 64, 100);
    try testing.expectEqual(Verdict.forward, result.verdict);
    try testing.expect(result.next_hop != null);
    try testing.expect(std.mem.eql(u8, &result.next_hop.?, &[4]u8{ 192, 168, 1, 254 }));
}

test "IpForwarder: decrementTtl" {
    // Minimal valid IPv4 header (20 bytes)
    var hdr: [20]u8 = .{0} ** 20;
    hdr[0] = 0x45; // IHL=5
    hdr[8] = 64; // TTL
    // Compute valid checksum first
    var cksum: u32 = 0;
    var i: usize = 0;
    while (i < 20) : (i += 2) {
        cksum += @as(u32, hdr[i]) << 8 | @as(u32, hdr[i + 1]);
    }
    while (cksum >> 16 != 0) {
        cksum = (cksum & 0xffff) + (cksum >> 16);
    }
    const cs = ~@as(u16, @intCast(cksum & 0xffff));
    hdr[10] = @intCast(cs >> 8);
    hdr[11] = @intCast(cs & 0xff);

    try testing.expect(IpForwarder.decrementTtl(&hdr));
    try testing.expectEqual(@as(u8, 63), hdr[8]);

    // Verify checksum is still valid
    var verify: u32 = 0;
    i = 0;
    while (i < 20) : (i += 2) {
        verify += @as(u32, hdr[i]) << 8 | @as(u32, hdr[i + 1]);
    }
    while (verify >> 16 != 0) {
        verify = (verify & 0xffff) + (verify >> 16);
    }
    try testing.expectEqual(@as(u32, 0xffff), verify);
}

test "IpForwarder: decrementTtl refuses TTL=1" {
    var hdr: [20]u8 = .{0} ** 20;
    hdr[0] = 0x45;
    hdr[8] = 1;
    try testing.expect(!IpForwarder.decrementTtl(&hdr));
}

test "IpForwarder: buildIcmpTimeExceeded" {
    // Fake original IP packet (28 bytes: 20 IP + 8 payload)
    var orig: [28]u8 = .{0} ** 28;
    orig[0] = 0x45;
    orig[8] = 1; // TTL that expired
    orig[12] = 10; // src
    orig[13] = 0;
    orig[14] = 0;
    orig[15] = 2;
    orig[16] = 192; // dst
    orig[17] = 168;
    orig[18] = 1;
    orig[19] = 1;

    var out: [100]u8 = undefined;
    const len = IpForwarder.buildIcmpTimeExceeded(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, &orig, &out);

    // Expected: 20 (IP) + 8 (ICMP) + 28 (orig) = 56
    try testing.expectEqual(@as(usize, 56), len);
    // Verify ICMP type=11, code=0
    try testing.expectEqual(@as(u8, 11), out[20]);
    try testing.expectEqual(@as(u8, 0), out[21]);
    // Verify IP protocol=1 (ICMP)
    try testing.expectEqual(@as(u8, 1), out[9]);
    // Verify original packet is included
    try testing.expect(std.mem.eql(u8, out[28..56], &orig));
}

test "IpForwarder: buildIcmpDestUnreachable" {
    var orig: [28]u8 = .{0} ** 28;
    orig[0] = 0x45;

    var out: [100]u8 = undefined;
    const len = IpForwarder.buildIcmpDestUnreachable(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, IcmpCode.host_unreachable, &orig, &out);
    try testing.expectEqual(@as(usize, 56), len);
    try testing.expectEqual(@as(u8, 3), out[20]); // type=3
    try testing.expectEqual(@as(u8, 1), out[21]); // code=1 host unreachable
}

test "IpForwarder: buildIcmpNeedFragment includes MTU" {
    var orig: [28]u8 = .{0} ** 28;
    orig[0] = 0x45;

    var out: [100]u8 = undefined;
    const len = IpForwarder.buildIcmpNeedFragment(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, 576, &orig, &out);
    try testing.expectEqual(@as(usize, 56), len);
    try testing.expectEqual(@as(u8, 3), out[20]); // type=3
    try testing.expectEqual(@as(u8, 4), out[21]); // code=4 frag needed
    // Next-Hop MTU in bytes 26-27 of packet (ICMP header bytes 6-7)
    const mtu_val = @as(u16, out[26]) << 8 | @as(u16, out[27]);
    try testing.expectEqual(@as(u16, 576), mtu_val);
}

test "IpForwarder: counters" {
    var fwd = IpForwarder.init();
    _ = fwd.addInterface(.{ 10, 0, 0, 1 }, 1500, true);
    const if1 = fwd.addInterface(.{ 192, 168, 1, 1 }, 1500, true).?;
    try testing.expect(fwd.routes.addRoute(route_mod.Prefix.fromIpv4(.{ 192, 168, 1, 0 }, 24), null, 0, if1));

    _ = fwd.forward(0, .{ 10, 0, 0, 2 }, .{ 192, 168, 1, 100 }, 0, 0, .any, 64, 100);
    _ = fwd.forward(0, .{ 10, 0, 0, 2 }, .{ 172, 16, 0, 1 }, 0, 0, .any, 64, 100); // no route

    try testing.expectEqual(@as(u64, 1), fwd.forwarded_count);
    try testing.expectEqual(@as(u64, 1), fwd.dropped_count);
}

test "IpForwarder: setForwarding toggle" {
    var fwd = IpForwarder.init();
    const if0 = fwd.addInterface(.{ 10, 0, 0, 1 }, 1500, true).?;
    const if1 = fwd.addInterface(.{ 192, 168, 1, 1 }, 1500, true).?;
    try testing.expect(fwd.routes.addRoute(route_mod.Prefix.fromIpv4(.{ 192, 168, 1, 0 }, 24), null, 0, if1));

    // Disable forwarding
    fwd.setForwarding(if0, false);
    const r1 = fwd.forward(if0, .{ 10, 0, 0, 2 }, .{ 192, 168, 1, 100 }, 0, 0, .any, 64, 100);
    try testing.expectEqual(Verdict.drop, r1.verdict);

    // Re-enable
    fwd.setForwarding(if0, true);
    const r2 = fwd.forward(if0, .{ 10, 0, 0, 2 }, .{ 192, 168, 1, 100 }, 0, 0, .any, 64, 100);
    try testing.expectEqual(Verdict.forward, r2.verdict);
}
