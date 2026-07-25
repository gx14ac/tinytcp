// SLAAC (Stateless Address Autoconfiguration, RFC 4862).
//
// Auto-configures IPv6 addresses from Router Advertisements:
// - Link-local address generation (EUI-64 from MAC)
// - Global address generation from RA prefix + interface ID
// - DAD (Duplicate Address Detection) via NS
// - Prefix lifetime tracking and address deprecation
//
// Sans-IO: produces NDP packets; caller sends them and feeds responses back.

const std = @import("std");
const ndp_mod = @import("ndp.zig");
const ipv6_header = @import("header/ipv6.zig");
const checksum_mod = @import("checksum.zig");

/// Maximum configured addresses.
const max_addresses: usize = 8;

/// Maximum tracked prefixes from RAs.
const max_prefixes: usize = 8;

/// DAD transmit count.
const dad_transmits: u8 = 1;

/// Retransmit timer for DAD NS (ms).
const dad_retrans_ms: u64 = 1_000;

/// Address state.
pub const AddrState = enum {
    tentative,
    preferred,
    deprecated,
};

/// A configured IPv6 address.
pub const Address = struct {
    addr: [16]u8 = .{0} ** 16,
    prefix_len: u8 = 0,
    state: AddrState = .tentative,
    active: bool = false,
    is_link_local: bool = false,
    valid_until_ms: u64 = 0,
    preferred_until_ms: u64 = 0,
    dad_probes_sent: u8 = 0,
    dad_start_ms: u64 = 0,
};

/// Prefix information from Router Advertisement.
pub const PrefixInfo = struct {
    prefix: [16]u8 = .{0} ** 16,
    prefix_len: u8 = 0,
    active: bool = false,
    on_link: bool = false,
    autonomous: bool = false,
    valid_lifetime_ms: u64 = 0,
    preferred_lifetime_ms: u64 = 0,
    received_ms: u64 = 0,
};

/// SLAAC output action.
pub const SlaacAction = union(enum) {
    none,
    /// Send an NDP packet (NS for DAD or RS).
    send: ndp_mod.SendBuf,
    /// Address confirmed (DAD completed successfully).
    addr_configured: [16]u8,
    /// Address conflicted (DAD detected duplicate).
    addr_conflict: [16]u8,
};

/// SLAAC state machine.
pub const Slaac = struct {
    addresses: [max_addresses]Address = [_]Address{.{}} ** max_addresses,
    prefixes: [max_prefixes]PrefixInfo = [_]PrefixInfo{.{}} ** max_prefixes,
    interface_id: [8]u8 = .{0} ** 8,
    local_mac: [6]u8 = .{0} ** 6,
    link_local_configured: bool = false,
    rs_sent: bool = false,

    pub fn init(mac: [6]u8) Slaac {
        var s = Slaac{};
        s.local_mac = mac;
        s.interface_id = macToEui64(mac);
        return s;
    }

    /// Start SLAAC: generate link-local and send RS.
    /// Returns a DAD NS for the tentative link-local address.
    pub fn start(self: *Slaac, now_ms: u64) SlaacAction {
        if (self.link_local_configured) return .none;

        // Generate link-local: fe80::interface_id
        var ll_addr: [16]u8 = .{0} ** 16;
        ll_addr[0] = 0xFE;
        ll_addr[1] = 0x80;
        @memcpy(ll_addr[8..16], &self.interface_id);

        // Add as tentative
        const idx = self.addAddress(ll_addr, 64, true, now_ms) orelse return .none;
        self.addresses[idx].valid_until_ms = std.math.maxInt(u64); // infinite
        self.addresses[idx].preferred_until_ms = std.math.maxInt(u64);

        // Send DAD NS (src = :: unspecified, target = ll_addr)
        return self.buildDadNS(ll_addr);
    }

    /// Process a Router Advertisement's Prefix Information option.
    /// `prefix` is the 128-bit prefix, `prefix_len` is the mask length.
    pub fn onPrefixInfo(
        self: *Slaac,
        now_ms: u64,
        prefix: [16]u8,
        prefix_len: u8,
        autonomous: bool,
        on_link: bool,
        valid_lifetime_s: u32,
        preferred_lifetime_s: u32,
    ) SlaacAction {
        // Store prefix
        self.updatePrefix(now_ms, prefix, prefix_len, autonomous, on_link, valid_lifetime_s, preferred_lifetime_s);

        if (!autonomous or prefix_len != 64) return .none;

        // Generate global address: prefix(64) + interface_id(64)
        var global_addr: [16]u8 = prefix;
        @memcpy(global_addr[8..16], &self.interface_id);

        // Check if already configured
        for (&self.addresses) |*a| {
            if (a.active and std.mem.eql(u8, &a.addr, &global_addr)) {
                // Update lifetimes
                a.valid_until_ms = if (valid_lifetime_s == 0xFFFFFFFF) std.math.maxInt(u64) else now_ms + @as(u64, valid_lifetime_s) * 1000;
                a.preferred_until_ms = if (preferred_lifetime_s == 0xFFFFFFFF) std.math.maxInt(u64) else now_ms + @as(u64, preferred_lifetime_s) * 1000;
                return .none;
            }
        }

        // New address — add as tentative and start DAD
        _ = self.addAddress(global_addr, prefix_len, false, now_ms) orelse return .none;
        return self.buildDadNS(global_addr);
    }

    /// Called when we receive a NA for one of our tentative addresses (DAD conflict).
    pub fn onDadConflict(self: *Slaac, addr: [16]u8) SlaacAction {
        for (&self.addresses) |*a| {
            if (a.active and std.mem.eql(u8, &a.addr, &addr) and a.state == .tentative) {
                a.active = false;
                if (a.is_link_local) {
                    self.link_local_configured = false;
                }
                return .{ .addr_conflict = addr };
            }
        }
        return .none;
    }

    /// Tick the SLAAC state machine.
    /// Manages DAD completion and address deprecation.
    pub fn tick(self: *Slaac, now_ms: u64) SlaacAction {
        for (&self.addresses) |*a| {
            if (!a.active) continue;

            switch (a.state) {
                .tentative => {
                    // DAD: after retrans_timer, if no conflict, address is confirmed
                    if (a.dad_probes_sent >= dad_transmits and
                        now_ms >= a.dad_start_ms + dad_retrans_ms)
                    {
                        a.state = .preferred;
                        if (a.is_link_local) {
                            self.link_local_configured = true;
                        }
                        return .{ .addr_configured = a.addr };
                    }
                },
                .preferred => {
                    if (a.preferred_until_ms != std.math.maxInt(u64) and
                        now_ms >= a.preferred_until_ms)
                    {
                        a.state = .deprecated;
                    }
                },
                .deprecated => {
                    if (a.valid_until_ms != std.math.maxInt(u64) and
                        now_ms >= a.valid_until_ms)
                    {
                        a.active = false;
                    }
                },
            }
        }
        return .none;
    }

    /// Get the link-local address (if configured).
    pub fn linkLocalAddr(self: *const Slaac) ?[16]u8 {
        for (&self.addresses) |*a| {
            if (a.active and a.is_link_local and a.state != .tentative) {
                return a.addr;
            }
        }
        return null;
    }

    /// Get a preferred global address (first one found).
    pub fn globalAddr(self: *const Slaac) ?[16]u8 {
        for (&self.addresses) |*a| {
            if (a.active and !a.is_link_local and a.state == .preferred) {
                return a.addr;
            }
        }
        return null;
    }

    /// Check if a given address belongs to us and is usable.
    pub fn hasAddress(self: *const Slaac, addr: [16]u8) bool {
        for (&self.addresses) |*a| {
            if (a.active and std.mem.eql(u8, &a.addr, &addr) and a.state != .tentative) {
                return true;
            }
        }
        return false;
    }

    // -- Internal --

    fn addAddress(self: *Slaac, addr: [16]u8, prefix_len: u8, is_link_local: bool, now_ms: u64) ?usize {
        for (&self.addresses, 0..) |*a, i| {
            if (!a.active) {
                a.* = .{
                    .addr = addr,
                    .prefix_len = prefix_len,
                    .state = .tentative,
                    .active = true,
                    .is_link_local = is_link_local,
                    .dad_start_ms = now_ms,
                    .dad_probes_sent = 1,
                };
                return i;
            }
        }
        return null;
    }

    fn updatePrefix(self: *Slaac, now_ms: u64, prefix: [16]u8, prefix_len: u8, autonomous: bool, on_link: bool, valid_s: u32, preferred_s: u32) void {
        // Update existing
        for (&self.prefixes) |*p| {
            if (p.active and p.prefix_len == prefix_len and prefixMatch(p.prefix, prefix, prefix_len)) {
                p.valid_lifetime_ms = if (valid_s == 0xFFFFFFFF) std.math.maxInt(u64) else @as(u64, valid_s) * 1000;
                p.preferred_lifetime_ms = if (preferred_s == 0xFFFFFFFF) std.math.maxInt(u64) else @as(u64, preferred_s) * 1000;
                p.received_ms = now_ms;
                return;
            }
        }
        // New prefix
        for (&self.prefixes) |*p| {
            if (!p.active) {
                p.* = .{
                    .prefix = prefix,
                    .prefix_len = prefix_len,
                    .active = true,
                    .on_link = on_link,
                    .autonomous = autonomous,
                    .valid_lifetime_ms = if (valid_s == 0xFFFFFFFF) std.math.maxInt(u64) else @as(u64, valid_s) * 1000,
                    .preferred_lifetime_ms = if (preferred_s == 0xFFFFFFFF) std.math.maxInt(u64) else @as(u64, preferred_s) * 1000,
                    .received_ms = now_ms,
                };
                return;
            }
        }
    }

    fn buildDadNS(self: *const Slaac, target: [16]u8) SlaacAction {
        const ip6_hlen: usize = 40;
        const icmp_len: usize = 24; // NS without options (DAD uses unspecified src, no SLLA)
        const total_len = ip6_hlen + icmp_len;

        var buf: ndp_mod.SendBuf = .{};
        if (total_len > buf.data.len) return .none;

        // IPv6 header: src = :: (unspecified), dst = solicited-node multicast
        const dst6 = ndp_mod.solicitedNodeMulticast(target);
        var ip6 = ipv6_header.MutableHeader.init(buf.data[0..ip6_hlen]) catch return .none;
        ip6.setPayloadLen(@intCast(icmp_len));
        ip6.setNextHeader(.icmpv6);
        ip6.setHopLimit(255);
        ip6.setSrcAddr(.{0} ** 16); // unspecified
        ip6.setDstAddr(dst6);

        // ICMPv6 NS
        const icmp_start = ip6_hlen;
        buf.data[icmp_start] = @intFromEnum(ndp_mod.NdpType.neighbor_solicitation);
        buf.data[icmp_start + 1] = 0;
        buf.data[icmp_start + 2] = 0; // checksum
        buf.data[icmp_start + 3] = 0;
        buf.data[icmp_start + 4] = 0; // reserved
        buf.data[icmp_start + 5] = 0;
        buf.data[icmp_start + 6] = 0;
        buf.data[icmp_start + 7] = 0;
        @memcpy(buf.data[icmp_start + 8 .. icmp_start + 24], &target);

        // ICMPv6 checksum (src = ::)
        buf.data[icmp_start + 2] = 0;
        buf.data[icmp_start + 3] = 0;
        const src_unspec: [16]u8 = .{0} ** 16;
        const ph = checksum_mod.pseudoHeaderIpv6(src_unspec, dst6, 58, @intCast(icmp_len));
        const sum = checksum_mod.accumulate(ph, buf.data[icmp_start .. icmp_start + icmp_len]);
        const cksum = checksum_mod.finish(sum);
        std.mem.writeInt(u16, buf.data[icmp_start + 2 ..][0..2], cksum, .big);

        buf.len = total_len;
        _ = self;
        return .{ .send = buf };
    }
};

/// Convert a 48-bit MAC to a 64-bit EUI-64 interface identifier.
pub fn macToEui64(mac: [6]u8) [8]u8 {
    return .{
        mac[0] ^ 0x02, // flip U/L bit
        mac[1],
        mac[2],
        0xFF,
        0xFE,
        mac[3],
        mac[4],
        mac[5],
    };
}

/// Check if two addresses match up to `prefix_len` bits.
fn prefixMatch(a: [16]u8, b: [16]u8, prefix_len: u8) bool {
    const full_bytes = prefix_len / 8;
    if (!std.mem.eql(u8, a[0..full_bytes], b[0..full_bytes])) return false;
    const rem_bits = prefix_len % 8;
    if (rem_bits > 0) {
        const mask: u8 = @as(u8, 0xFF) << @intCast(8 - rem_bits);
        if ((a[full_bytes] & mask) != (b[full_bytes] & mask)) return false;
    }
    return true;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "macToEui64" {
    const mac = [6]u8{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E };
    const eui64 = macToEui64(mac);
    // First byte: 0x00 XOR 0x02 = 0x02
    try testing.expectEqual(@as(u8, 0x02), eui64[0]);
    try testing.expectEqual(@as(u8, 0x1A), eui64[1]);
    try testing.expectEqual(@as(u8, 0x2B), eui64[2]);
    try testing.expectEqual(@as(u8, 0xFF), eui64[3]);
    try testing.expectEqual(@as(u8, 0xFE), eui64[4]);
    try testing.expectEqual(@as(u8, 0x3C), eui64[5]);
    try testing.expectEqual(@as(u8, 0x4D), eui64[6]);
    try testing.expectEqual(@as(u8, 0x5E), eui64[7]);
}

test "SLAAC: start generates link-local and DAD NS" {
    var slaac = Slaac.init(.{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E });
    const action = slaac.start(0);

    switch (action) {
        .send => |buf| {
            try testing.expect(buf.len > 40);
            // ICMPv6 type = 135 (NS)
            try testing.expectEqual(@as(u8, 135), buf.data[40]);
            // Source should be :: (all zeros)
            const src = buf.data[8..24];
            for (src) |b| try testing.expectEqual(@as(u8, 0), b);
        },
        else => return error.TestUnexpectedResult,
    }

    // Address should be tentative
    try testing.expect(slaac.linkLocalAddr() == null); // not yet confirmed
}

test "SLAAC: DAD completes → address confirmed" {
    var slaac = Slaac.init(.{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E });
    _ = slaac.start(0);

    // Tick past DAD timer (no conflict received)
    const result = slaac.tick(dad_retrans_ms + 1);
    switch (result) {
        .addr_configured => |addr| {
            // Should be link-local
            try testing.expectEqual(@as(u8, 0xFE), addr[0]);
            try testing.expectEqual(@as(u8, 0x80), addr[1]);
        },
        else => return error.TestUnexpectedResult,
    }

    // Link-local should now be available
    try testing.expect(slaac.linkLocalAddr() != null);
}

test "SLAAC: DAD conflict" {
    var slaac = Slaac.init(.{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E });
    _ = slaac.start(0);

    // Derive the tentative link-local
    var ll: [16]u8 = .{0} ** 16;
    ll[0] = 0xFE;
    ll[1] = 0x80;
    @memcpy(ll[8..16], &macToEui64(slaac.local_mac));

    // Simulate conflict
    const result = slaac.onDadConflict(ll);
    switch (result) {
        .addr_conflict => |addr| {
            try testing.expectEqualSlices(u8, &ll, &addr);
        },
        else => return error.TestUnexpectedResult,
    }

    // Address should not be configured
    try testing.expect(slaac.linkLocalAddr() == null);
    try testing.expect(!slaac.link_local_configured);
}

test "SLAAC: prefix info generates global address" {
    var slaac = Slaac.init(.{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E });
    // Simulate link-local already configured
    slaac.link_local_configured = true;
    slaac.addresses[0] = .{
        .addr = .{ 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x1A, 0x2B, 0xFF, 0xFE, 0x3C, 0x4D, 0x5E },
        .prefix_len = 64,
        .state = .preferred,
        .active = true,
        .is_link_local = true,
        .valid_until_ms = std.math.maxInt(u64),
        .preferred_until_ms = std.math.maxInt(u64),
    };

    // Receive prefix 2001:db8::/64
    var prefix: [16]u8 = .{0} ** 16;
    prefix[0] = 0x20;
    prefix[1] = 0x01;
    prefix[2] = 0x0d;
    prefix[3] = 0xb8;

    const action = slaac.onPrefixInfo(1000, prefix, 64, true, true, 7200, 3600);
    switch (action) {
        .send => |buf| {
            // Should be DAD NS for the new global address
            try testing.expectEqual(@as(u8, 135), buf.data[40]);
        },
        else => return error.TestUnexpectedResult,
    }

    // After DAD completes
    const tick_result = slaac.tick(1000 + dad_retrans_ms + 1);
    switch (tick_result) {
        .addr_configured => |addr| {
            // Should be 2001:db8::0021a:2bff:fe3c:4d5e
            try testing.expectEqual(@as(u8, 0x20), addr[0]);
            try testing.expectEqual(@as(u8, 0x01), addr[1]);
        },
        else => return error.TestUnexpectedResult,
    }

    try testing.expect(slaac.globalAddr() != null);
}

test "SLAAC: address deprecation" {
    var slaac = Slaac.init(.{ 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E });

    // Manually add a preferred address with short lifetime
    slaac.addresses[0] = .{
        .addr = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0x02, 0x1A, 0x2B, 0xFF, 0xFE, 0x3C, 0x4D, 0x5E },
        .prefix_len = 64,
        .state = .preferred,
        .active = true,
        .valid_until_ms = 10000,
        .preferred_until_ms = 5000,
    };

    // Tick past preferred lifetime → deprecated
    _ = slaac.tick(5001);
    try testing.expectEqual(AddrState.deprecated, slaac.addresses[0].state);

    // Tick past valid lifetime → removed
    _ = slaac.tick(10001);
    try testing.expect(!slaac.addresses[0].active);
}

test "prefixMatch" {
    const a = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const b = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    const c = [16]u8{ 0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    try testing.expect(prefixMatch(a, b, 64));
    try testing.expect(!prefixMatch(a, c, 64));
    try testing.expect(prefixMatch(a, c, 24)); // first 3 bytes match
}
