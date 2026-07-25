// NDP (Neighbor Discovery Protocol, RFC 4861).
//
// Implements IPv6 neighbor resolution (replaces ARP for IPv6):
// - Neighbor Solicitation / Advertisement
// - Router Solicitation / Advertisement
// - Neighbor Cache with reachability states
//
// Sans-IO: produces ICMPv6/NDP packets as byte slices; caller sends them.

const std = @import("std");
const checksum_mod = @import("checksum.zig");
const ipv6_header = @import("header/ipv6.zig");

/// Maximum neighbor cache entries.
const max_entries: usize = 64;

/// Reachable timeout (ms).
const reachable_timeout_ms: u64 = 30_000;

/// Stale → Delay timeout (ms) — triggers probe on next send.
const delay_timeout_ms: u64 = 5_000;

/// Retransmit timer for probes (ms).
const retrans_timer_ms: u64 = 1_000;

/// Maximum unicast probes before declaring unreachable.
const max_unicast_probes: u8 = 3;

/// ICMPv6 NDP message types.
pub const NdpType = enum(u8) {
    router_solicitation = 133,
    router_advertisement = 134,
    neighbor_solicitation = 135,
    neighbor_advertisement = 136,
    redirect = 137,
    _,
};

/// Neighbor cache entry states (RFC 4861 §7.3.2).
pub const NeighborState = enum {
    incomplete,
    reachable,
    stale,
    delay,
    probe,
};

/// A single neighbor cache entry.
pub const NeighborEntry = struct {
    ip6: [16]u8 = .{0} ** 16,
    mac: [6]u8 = .{0} ** 6,
    state: NeighborState = .incomplete,
    active: bool = false,
    is_router: bool = false,
    last_confirmed_ms: u64 = 0,
    last_probe_ms: u64 = 0,
    probes_sent: u8 = 0,
};

/// NDP output action.
pub const NdpAction = union(enum) {
    none,
    /// Send an ICMPv6/NDP packet (IPv6 header + ICMPv6 payload).
    send: SendBuf,
};

/// Buffer for an outbound NDP packet (IPv6 + ICMPv6).
pub const SendBuf = struct {
    data: [128]u8 = undefined,
    len: usize = 0,
};

/// Solicited-node multicast address: ff02::1:ffXX:XXXX (last 3 bytes of unicast).
pub fn solicitedNodeMulticast(addr: [16]u8) [16]u8 {
    var mcast: [16]u8 = .{0} ** 16;
    mcast[0] = 0xFF;
    mcast[1] = 0x02;
    mcast[11] = 0x01;
    mcast[12] = 0xFF;
    mcast[13] = addr[13];
    mcast[14] = addr[14];
    mcast[15] = addr[15];
    return mcast;
}

/// NDP neighbor cache and protocol handler.
pub const NdpCache = struct {
    entries: [max_entries]NeighborEntry = [_]NeighborEntry{.{}} ** max_entries,
    local_ip6: [16]u8 = .{0} ** 16,
    local_mac: [6]u8 = .{0} ** 6,

    pub fn init(local_ip6: [16]u8, local_mac: [6]u8) NdpCache {
        return .{ .local_ip6 = local_ip6, .local_mac = local_mac };
    }

    /// Look up MAC for an IPv6 address. Returns null if not resolved.
    pub fn lookup(self: *const NdpCache, ip6: [16]u8) ?[6]u8 {
        for (&self.entries) |*e| {
            if (e.active and std.mem.eql(u8, &e.ip6, &ip6)) {
                if (e.state != .incomplete) return e.mac;
            }
        }
        return null;
    }

    /// Get current state of a neighbor entry.
    pub fn getState(self: *const NdpCache, ip6: [16]u8) ?NeighborState {
        for (&self.entries) |*e| {
            if (e.active and std.mem.eql(u8, &e.ip6, &ip6)) return e.state;
        }
        return null;
    }

    /// Process an incoming NDP packet (ICMPv6 payload, after IPv6 header).
    /// `src6` and `dst6` are from the IPv6 header (for validation).
    pub fn onPacket(self: *NdpCache, now_ms: u64, src6: [16]u8, _: [16]u8, icmp_data: []const u8) NdpAction {
        if (icmp_data.len < 4) return .none;
        const msg_type: NdpType = @enumFromInt(icmp_data[0]);

        switch (msg_type) {
            .neighbor_solicitation => return self.handleNS(now_ms, src6, icmp_data),
            .neighbor_advertisement => {
                self.handleNA(now_ms, icmp_data);
                return .none;
            },
            .router_advertisement => {
                self.handleRA(now_ms, src6, icmp_data);
                return .none;
            },
            else => return .none,
        }
    }

    /// Initiate neighbor resolution by sending a Neighbor Solicitation.
    pub fn resolve(self: *NdpCache, now_ms: u64, target_ip6: [16]u8) NdpAction {
        // Find or create entry
        var entry_idx: ?usize = null;
        for (&self.entries, 0..) |*e, i| {
            if (e.active and std.mem.eql(u8, &e.ip6, &target_ip6)) {
                entry_idx = i;
                break;
            }
        }

        if (entry_idx == null) {
            // Allocate new entry in INCOMPLETE state
            for (&self.entries, 0..) |*e, i| {
                if (!e.active) {
                    e.* = .{
                        .ip6 = target_ip6,
                        .active = true,
                        .state = .incomplete,
                        .last_probe_ms = now_ms,
                        .probes_sent = 1,
                    };
                    entry_idx = i;
                    break;
                }
            }
        }

        if (entry_idx == null) return .none;

        return self.buildNS(target_ip6);
    }

    /// Tick the neighbor cache — manage state transitions and retransmissions.
    /// Returns an action if a probe needs to be sent.
    pub fn tick(self: *NdpCache, now_ms: u64) NdpAction {
        for (&self.entries) |*e| {
            if (!e.active) continue;

            switch (e.state) {
                .reachable => {
                    if (now_ms >= e.last_confirmed_ms + reachable_timeout_ms) {
                        e.state = .stale;
                    }
                },
                .delay => {
                    if (now_ms >= e.last_probe_ms + delay_timeout_ms) {
                        e.state = .probe;
                        e.probes_sent = 0;
                        e.last_probe_ms = now_ms;
                    }
                },
                .probe => {
                    if (now_ms >= e.last_probe_ms + retrans_timer_ms) {
                        if (e.probes_sent >= max_unicast_probes) {
                            e.active = false;
                        } else {
                            e.probes_sent += 1;
                            e.last_probe_ms = now_ms;
                            return self.buildNS(e.ip6);
                        }
                    }
                },
                .incomplete => {
                    if (now_ms >= e.last_probe_ms + retrans_timer_ms) {
                        if (e.probes_sent >= max_unicast_probes) {
                            e.active = false;
                        } else {
                            e.probes_sent += 1;
                            e.last_probe_ms = now_ms;
                            return self.buildNS(e.ip6);
                        }
                    }
                },
                .stale => {},
            }
        }
        return .none;
    }

    /// Build a Router Solicitation message.
    pub fn buildRS(self: *const NdpCache) NdpAction {
        const ip6_hlen: usize = 40;
        const icmp_len: usize = 8 + 8; // RS(8 bytes) + source link-layer option (8 bytes)
        const total_len = ip6_hlen + icmp_len;

        var buf: SendBuf = .{};
        if (total_len > buf.data.len) return .none;

        // IPv6 header: src=local, dst=ff02::2 (all-routers)
        var ip6 = ipv6_header.MutableHeader.init(buf.data[0..ip6_hlen]) catch return .none;
        ip6.setPayloadLen(@intCast(icmp_len));
        ip6.setNextHeader(.icmpv6);
        ip6.setHopLimit(255);
        ip6.setSrcAddr(self.local_ip6);
        var all_routers: [16]u8 = .{0} ** 16;
        all_routers[0] = 0xFF;
        all_routers[1] = 0x02;
        all_routers[15] = 0x02;
        ip6.setDstAddr(all_routers);

        // ICMPv6 Router Solicitation
        const icmp_start = ip6_hlen;
        buf.data[icmp_start] = @intFromEnum(NdpType.router_solicitation);
        buf.data[icmp_start + 1] = 0; // code
        buf.data[icmp_start + 2] = 0; // checksum (computed below)
        buf.data[icmp_start + 3] = 0;
        buf.data[icmp_start + 4] = 0; // reserved
        buf.data[icmp_start + 5] = 0;
        buf.data[icmp_start + 6] = 0;
        buf.data[icmp_start + 7] = 0;

        // Source Link-Layer Address option (type=1, len=1 (8 bytes))
        buf.data[icmp_start + 8] = 1; // type
        buf.data[icmp_start + 9] = 1; // length (in 8-byte units)
        @memcpy(buf.data[icmp_start + 10 .. icmp_start + 16], &self.local_mac);

        // Compute ICMPv6 checksum
        self.computeIcmpv6Checksum(buf.data[0..total_len], icmp_start, icmp_len, all_routers);

        buf.len = total_len;
        return .{ .send = buf };
    }

    // -- Internal handlers --

    fn handleNS(self: *NdpCache, now_ms: u64, src6: [16]u8, icmp_data: []const u8) NdpAction {
        // NS format: type(1) + code(1) + checksum(2) + reserved(4) + target(16) = 24 bytes min
        if (icmp_data.len < 24) return .none;

        const target = icmp_data[8..24].*;

        // Only respond if target is our address
        if (!std.mem.eql(u8, &target, &self.local_ip6)) return .none;

        // Learn sender's link-layer address from options (if present)
        if (icmp_data.len >= 32) {
            const opt_type = icmp_data[24];
            const opt_len = icmp_data[25];
            if (opt_type == 1 and opt_len == 1) { // Source Link-Layer Address
                const sender_mac = icmp_data[26..32].*;
                self.updateEntry(now_ms, src6, sender_mac, false);
            }
        }

        // Build Neighbor Advertisement reply
        return self.buildNA(src6, target, true);
    }

    fn handleNA(self: *NdpCache, now_ms: u64, icmp_data: []const u8) void {
        // NA format: type(1) + code(1) + checksum(2) + flags(4) + target(16) = 24 bytes min
        if (icmp_data.len < 24) return;

        const flags_byte = icmp_data[4];
        const is_router = (flags_byte & 0x80) != 0;
        // const solicited = (flags_byte & 0x40) != 0;
        const override = (flags_byte & 0x20) != 0;

        const target = icmp_data[8..24].*;

        // Extract Target Link-Layer Address option
        var mac: ?[6]u8 = null;
        if (icmp_data.len >= 32) {
            const opt_type = icmp_data[24];
            const opt_len = icmp_data[25];
            if (opt_type == 2 and opt_len == 1) { // Target Link-Layer Address
                mac = icmp_data[26..32].*;
            }
        }

        // Find entry
        for (&self.entries) |*e| {
            if (!e.active or !std.mem.eql(u8, &e.ip6, &target)) continue;

            if (mac) |m| {
                if (e.state == .incomplete) {
                    e.mac = m;
                    e.state = .reachable;
                    e.last_confirmed_ms = now_ms;
                    e.is_router = is_router;
                } else if (override or std.mem.eql(u8, &e.mac, &m)) {
                    e.mac = m;
                    e.state = .reachable;
                    e.last_confirmed_ms = now_ms;
                    e.is_router = is_router;
                } else {
                    e.state = .stale;
                }
            }
            return;
        }

        // No existing entry — create one if we have a MAC
        if (mac) |m| {
            self.updateEntry(now_ms, target, m, is_router);
        }
    }

    fn handleRA(self: *NdpCache, now_ms: u64, src6: [16]u8, icmp_data: []const u8) void {
        // RA format: type(1) + code(1) + checksum(2) + hop_limit(1) + flags(1) +
        //            router_lifetime(2) + reachable_time(4) + retrans_timer(4) = 16 bytes min
        if (icmp_data.len < 16) return;

        // Extract source link-layer address from options
        var offset: usize = 16;
        while (offset + 2 <= icmp_data.len) {
            const opt_type = icmp_data[offset];
            const opt_len = icmp_data[offset + 1];
            if (opt_len == 0) break;
            const opt_total = @as(usize, opt_len) * 8;
            if (offset + opt_total > icmp_data.len) break;

            if (opt_type == 1 and opt_len == 1 and offset + 8 <= icmp_data.len) {
                // Source Link-Layer Address
                const router_mac: [6]u8 = icmp_data[offset + 2 ..][0..6].*;
                self.updateEntry(now_ms, src6, router_mac, true);
                return;
            }
            offset += opt_total;
        }

        // Even without SLLA option, mark router as known
        for (&self.entries) |*e| {
            if (e.active and std.mem.eql(u8, &e.ip6, &src6)) {
                e.is_router = true;
                return;
            }
        }
    }

    fn buildNA(self: *const NdpCache, dst6: [16]u8, target: [16]u8, solicited: bool) NdpAction {
        const ip6_hlen: usize = 40;
        const icmp_len: usize = 24 + 8; // NA(24 bytes) + target link-layer option (8 bytes)
        const total_len = ip6_hlen + icmp_len;

        var buf: SendBuf = .{};
        if (total_len > buf.data.len) return .none;

        // IPv6 header
        var ip6 = ipv6_header.MutableHeader.init(buf.data[0..ip6_hlen]) catch return .none;
        ip6.setPayloadLen(@intCast(icmp_len));
        ip6.setNextHeader(.icmpv6);
        ip6.setHopLimit(255);
        ip6.setSrcAddr(self.local_ip6);
        ip6.setDstAddr(dst6);

        // ICMPv6 Neighbor Advertisement
        const icmp_start = ip6_hlen;
        buf.data[icmp_start] = @intFromEnum(NdpType.neighbor_advertisement);
        buf.data[icmp_start + 1] = 0; // code
        buf.data[icmp_start + 2] = 0; // checksum
        buf.data[icmp_start + 3] = 0;
        // Flags: R=0, S=solicited, O=1 (override)
        buf.data[icmp_start + 4] = if (solicited) 0x60 else 0x20;
        buf.data[icmp_start + 5] = 0;
        buf.data[icmp_start + 6] = 0;
        buf.data[icmp_start + 7] = 0;
        // Target address
        @memcpy(buf.data[icmp_start + 8 .. icmp_start + 24], &target);

        // Target Link-Layer Address option (type=2, len=1)
        buf.data[icmp_start + 24] = 2; // type
        buf.data[icmp_start + 25] = 1; // length (in 8-byte units)
        @memcpy(buf.data[icmp_start + 26 .. icmp_start + 32], &self.local_mac);

        // Compute ICMPv6 checksum
        self.computeIcmpv6Checksum(buf.data[0..total_len], icmp_start, icmp_len, dst6);

        buf.len = total_len;
        return .{ .send = buf };
    }

    fn buildNS(self: *const NdpCache, target: [16]u8) NdpAction {
        const ip6_hlen: usize = 40;
        const icmp_len: usize = 24 + 8; // NS(24 bytes) + source link-layer option (8 bytes)
        const total_len = ip6_hlen + icmp_len;

        var buf: SendBuf = .{};
        if (total_len > buf.data.len) return .none;

        // Destination: solicited-node multicast
        const dst6 = solicitedNodeMulticast(target);

        // IPv6 header
        var ip6 = ipv6_header.MutableHeader.init(buf.data[0..ip6_hlen]) catch return .none;
        ip6.setPayloadLen(@intCast(icmp_len));
        ip6.setNextHeader(.icmpv6);
        ip6.setHopLimit(255);
        ip6.setSrcAddr(self.local_ip6);
        ip6.setDstAddr(dst6);

        // ICMPv6 Neighbor Solicitation
        const icmp_start = ip6_hlen;
        buf.data[icmp_start] = @intFromEnum(NdpType.neighbor_solicitation);
        buf.data[icmp_start + 1] = 0; // code
        buf.data[icmp_start + 2] = 0; // checksum
        buf.data[icmp_start + 3] = 0;
        buf.data[icmp_start + 4] = 0; // reserved
        buf.data[icmp_start + 5] = 0;
        buf.data[icmp_start + 6] = 0;
        buf.data[icmp_start + 7] = 0;
        // Target address
        @memcpy(buf.data[icmp_start + 8 .. icmp_start + 24], &target);

        // Source Link-Layer Address option (type=1, len=1)
        buf.data[icmp_start + 24] = 1; // type
        buf.data[icmp_start + 25] = 1; // length (in 8-byte units)
        @memcpy(buf.data[icmp_start + 26 .. icmp_start + 32], &self.local_mac);

        // Compute ICMPv6 checksum
        self.computeIcmpv6Checksum(buf.data[0..total_len], icmp_start, icmp_len, dst6);

        buf.len = total_len;
        return .{ .send = buf };
    }

    fn computeIcmpv6Checksum(self: *const NdpCache, pkt: []u8, icmp_start: usize, icmp_len: usize, dst: [16]u8) void {
        pkt[icmp_start + 2] = 0;
        pkt[icmp_start + 3] = 0;
        const ph = checksum_mod.pseudoHeaderIpv6(self.local_ip6, dst, 58, @intCast(icmp_len));
        const sum = checksum_mod.accumulate(ph, pkt[icmp_start .. icmp_start + icmp_len]);
        const cksum = checksum_mod.finish(sum);
        std.mem.writeInt(u16, pkt[icmp_start + 2 ..][0..2], cksum, .big);
    }

    fn updateEntry(self: *NdpCache, now_ms: u64, ip6: [16]u8, mac: [6]u8, is_router: bool) void {
        // Update existing
        for (&self.entries) |*e| {
            if (e.active and std.mem.eql(u8, &e.ip6, &ip6)) {
                e.mac = mac;
                e.state = .reachable;
                e.last_confirmed_ms = now_ms;
                e.is_router = is_router;
                return;
            }
        }
        // Find empty slot
        for (&self.entries) |*e| {
            if (!e.active) {
                e.* = .{
                    .ip6 = ip6,
                    .mac = mac,
                    .active = true,
                    .state = .reachable,
                    .last_confirmed_ms = now_ms,
                    .is_router = is_router,
                };
                return;
            }
        }
        // Evict oldest stale
        var oldest_idx: ?usize = null;
        var oldest_ts: u64 = std.math.maxInt(u64);
        for (&self.entries, 0..) |*e, i| {
            if (e.state == .stale and e.last_confirmed_ms < oldest_ts) {
                oldest_ts = e.last_confirmed_ms;
                oldest_idx = i;
            }
        }
        if (oldest_idx) |idx| {
            self.entries[idx] = .{
                .ip6 = ip6,
                .mac = mac,
                .active = true,
                .state = .reachable,
                .last_confirmed_ms = now_ms,
                .is_router = is_router,
            };
        }
    }

    /// Confirm reachability (called when upper-layer confirms communication).
    pub fn confirmReachability(self: *NdpCache, now_ms: u64, ip6: [16]u8) void {
        for (&self.entries) |*e| {
            if (e.active and std.mem.eql(u8, &e.ip6, &ip6)) {
                e.state = .reachable;
                e.last_confirmed_ms = now_ms;
                return;
            }
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "NdpCache: resolve triggers NS" {
    var cache = NdpCache.init(
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
    );

    const target = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    const action = cache.resolve(0, target);

    switch (action) {
        .send => |buf| {
            try testing.expect(buf.len > 40);
            // Verify it's an NS (ICMPv6 type 135)
            try testing.expectEqual(@as(u8, 135), buf.data[40]);
        },
        .none => return error.TestUnexpectedResult,
    }

    // Entry should be in INCOMPLETE state
    try testing.expectEqual(NeighborState.incomplete, cache.getState(target).?);
}

test "NdpCache: NA resolves entry" {
    var cache = NdpCache.init(
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
    );

    const target = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    _ = cache.resolve(0, target);

    // Simulate receiving NA with target link-layer address
    var na_pkt: [32]u8 = .{0} ** 32;
    na_pkt[0] = @intFromEnum(NdpType.neighbor_advertisement);
    na_pkt[1] = 0; // code
    na_pkt[4] = 0x60; // flags: S + O
    @memcpy(na_pkt[8..24], &target); // target address
    na_pkt[24] = 2; // option type: Target Link-Layer Address
    na_pkt[25] = 1; // option length
    const peer_mac = [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    @memcpy(na_pkt[26..32], &peer_mac);

    const src6 = target; // NA comes from the target
    _ = cache.onPacket(100, src6, cache.local_ip6, &na_pkt);

    // Entry should now be REACHABLE with the correct MAC
    try testing.expectEqual(NeighborState.reachable, cache.getState(target).?);
    const mac = cache.lookup(target);
    try testing.expect(mac != null);
    try testing.expectEqualSlices(u8, &peer_mac, &mac.?);
}

test "NdpCache: NS for our address generates NA" {
    var cache = NdpCache.init(
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
    );

    // Build NS asking for our address
    var ns_pkt: [32]u8 = .{0} ** 32;
    ns_pkt[0] = @intFromEnum(NdpType.neighbor_solicitation);
    ns_pkt[1] = 0;
    @memcpy(ns_pkt[8..24], &cache.local_ip6); // target = our address
    ns_pkt[24] = 1; // Source Link-Layer Address option
    ns_pkt[25] = 1;
    const sender_mac = [6]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    @memcpy(ns_pkt[26..32], &sender_mac);

    const sender_ip = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    const action = cache.onPacket(100, sender_ip, cache.local_ip6, &ns_pkt);

    switch (action) {
        .send => |buf| {
            // Should be an NA (type 136)
            try testing.expectEqual(@as(u8, 136), buf.data[40]);
            // Sender should have been learned
            const learned_mac = cache.lookup(sender_ip);
            try testing.expect(learned_mac != null);
            try testing.expectEqualSlices(u8, &sender_mac, &learned_mac.?);
        },
        .none => return error.TestUnexpectedResult,
    }
}

test "NdpCache: state transitions (reachable → stale)" {
    var cache = NdpCache.init(
        .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF },
    );

    const target = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

    // Manually insert a reachable entry
    cache.entries[0] = .{
        .ip6 = target,
        .mac = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
        .active = true,
        .state = .reachable,
        .last_confirmed_ms = 0,
    };

    // Tick past reachable timeout
    _ = cache.tick(reachable_timeout_ms + 1);
    try testing.expectEqual(NeighborState.stale, cache.getState(target).?);
}

test "NdpCache: solicited-node multicast" {
    const addr = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34 };
    const mcast = solicitedNodeMulticast(addr);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, 0, 0x12, 0x34 }, &mcast);
}

test "NdpCache: Router Solicitation" {
    const cache = NdpCache.init(
        .{ 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 },
    );

    const action = cache.buildRS();
    switch (action) {
        .send => |buf| {
            try testing.expect(buf.len > 40);
            // ICMPv6 type = 133 (Router Solicitation)
            try testing.expectEqual(@as(u8, 133), buf.data[40]);
        },
        .none => return error.TestUnexpectedResult,
    }
}
