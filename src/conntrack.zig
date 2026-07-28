// Connection Tracking (conntrack) — Stateful packet filter layer.
//
// Tracks TCP/UDP connection state and auto-allows return traffic for
// established connections. Provides NAT translation (SNAT/DNAT).
//
// Sans-IO: caller drives with timestamps; no I/O, no allocations.
// IPv4 only. IPv6 conntrack is a future extension.
//
// Modeled after Linux nf_conntrack:
// - 5-tuple connection identification
// - TCP state machine (NEW → ESTABLISHED → CLOSING → CLOSED)
// - Timeout-based expiry
// - SNAT/DNAT rewriting

const std = @import("std");

/// Connection state.
pub const ConnState = enum {
    new,
    established,
    related,
    closing,
    closed,
};

/// Transport protocol for conntrack.
pub const Protocol = enum {
    tcp,
    udp,
    icmp,
};

/// 5-tuple identifying a connection (directional).
pub const Tuple = struct {
    src_addr: [4]u8,
    dst_addr: [4]u8,
    src_port: u16,
    dst_port: u16,
    protocol: Protocol,

    pub fn reverse(self: Tuple) Tuple {
        return .{
            .src_addr = self.dst_addr,
            .dst_addr = self.src_addr,
            .src_port = self.dst_port,
            .dst_port = self.src_port,
            .protocol = self.protocol,
        };
    }

    pub fn eql(a: Tuple, b: Tuple) bool {
        return std.mem.eql(u8, &a.src_addr, &b.src_addr) and
            std.mem.eql(u8, &a.dst_addr, &b.dst_addr) and
            a.src_port == b.src_port and
            a.dst_port == b.dst_port and
            a.protocol == b.protocol;
    }
};

/// NAT type.
pub const NatType = enum {
    none,
    snat,
    dnat,
};

/// NAT translation info.
pub const NatInfo = struct {
    nat_type: NatType = .none,
    /// Translated address (SNAT: new src, DNAT: new dst).
    addr: [4]u8 = .{ 0, 0, 0, 0 },
    /// Translated port.
    port: u16 = 0,
};

/// Maximum connection tracking entries.
const max_entries: usize = 256;

/// Timeout constants (milliseconds).
pub const Timeouts = struct {
    pub const tcp_new: u64 = 30_000; // 30s for SYN-only
    pub const tcp_established: u64 = 300_000; // 5 min
    pub const tcp_closing: u64 = 60_000; // 1 min for FIN/RST
    pub const udp_stream: u64 = 120_000; // 2 min
    pub const udp_single: u64 = 30_000; // 30s one-shot
    pub const icmp: u64 = 30_000; // 30s
};

/// Per-flow traffic statistics.
pub const ConnStats = struct {
    packets_orig: u32 = 0,
    packets_reply: u32 = 0,
    bytes_orig: u64 = 0,
    bytes_reply: u64 = 0,
};

/// A connection tracking entry.
pub const ConnEntry = struct {
    active: bool = false,
    original: Tuple = std.mem.zeroes(Tuple),
    reply: Tuple = std.mem.zeroes(Tuple),
    state: ConnState = .new,
    last_seen: u64 = 0,
    timeout: u64 = 0,
    nat: NatInfo = .{},
    /// Number of packets seen.
    packet_count: u32 = 0,
    /// Per-flow traffic counters.
    stats: ConnStats = .{},

    pub fn protocol(self: *const ConnEntry) Protocol {
        return self.original.protocol;
    }
};

/// Conntrack verdict.
pub const Verdict = enum {
    allow,
    /// Returned for tracked connections in .closed state (RST received after tracking).
    deny,
    no_match,
};

/// Connection tracker.
pub const ConnTrack = struct {
    entries: [max_entries]ConnEntry = [_]ConnEntry{.{}} ** max_entries,
    entry_count: usize = 0,

    pub fn init() ConnTrack {
        return .{};
    }

    /// Look up a connection by its original or reply tuple.
    /// Returns the entry index if found.
    pub fn lookup(self: *const ConnTrack, tuple: Tuple) ?usize {
        for (&self.entries, 0..) |*entry, i| {
            if (!entry.active) continue;
            if (Tuple.eql(entry.original, tuple) or Tuple.eql(entry.reply, tuple)) {
                return i;
            }
        }
        return null;
    }

    /// Create or update a connection entry.
    /// For new connections, creates an entry in NEW state.
    /// For existing connections, updates state and timestamp.
    /// Returns the entry index, or null if table is full.
    pub fn track(self: *ConnTrack, tuple: Tuple, now_ms: u64, is_reply: bool) ?usize {
        return self.trackWithSize(tuple, now_ms, is_reply, 0);
    }

    /// Like track(), but also records packet byte count for stats.
    pub fn trackWithSize(self: *ConnTrack, tuple: Tuple, now_ms: u64, is_reply: bool, pkt_size: u32) ?usize {
        // Check existing
        if (self.lookup(tuple)) |idx| {
            var entry = &self.entries[idx];
            entry.last_seen = now_ms;
            entry.packet_count += 1;
            if (is_reply) {
                entry.stats.packets_reply += 1;
                entry.stats.bytes_reply += pkt_size;
            } else {
                entry.stats.packets_orig += 1;
                entry.stats.bytes_orig += pkt_size;
            }

            if (is_reply and entry.state == .new) {
                entry.state = .established;
                entry.timeout = switch (entry.protocol()) {
                    .tcp => Timeouts.tcp_established,
                    .udp => Timeouts.udp_stream,
                    .icmp => Timeouts.icmp,
                };
            }

            // UDP: promote to stream timeout only if bidirectional (ESTABLISHED)
            if (entry.protocol() == .udp and entry.state == .established) {
                entry.timeout = Timeouts.udp_stream;
            }

            return idx;
        }

        // New connection
        for (&self.entries, 0..) |*entry, i| {
            if (!entry.active) {
                entry.* = .{
                    .active = true,
                    .original = tuple,
                    .reply = tuple.reverse(),
                    .state = .new,
                    .last_seen = now_ms,
                    .timeout = switch (tuple.protocol) {
                        .tcp => Timeouts.tcp_new,
                        .udp => Timeouts.udp_single,
                        .icmp => Timeouts.icmp,
                    },
                    .packet_count = 1,
                    .stats = .{
                        .packets_orig = 1,
                        .bytes_orig = pkt_size,
                    },
                };
                self.entry_count += 1;
                return i;
            }
        }
        return null;
    }

    /// Mark a TCP connection as closing (FIN/RST seen). No-op for non-TCP entries.
    pub fn markClosing(self: *ConnTrack, tuple: Tuple, now_ms: u64) void {
        if (self.lookup(tuple)) |idx| {
            if (self.entries[idx].protocol() != .tcp) return;
            self.entries[idx].state = .closing;
            self.entries[idx].last_seen = now_ms;
            self.entries[idx].timeout = Timeouts.tcp_closing;
        }
    }

    /// Mark a connection as closed (remove immediately).
    pub fn remove(self: *ConnTrack, tuple: Tuple) void {
        if (self.lookup(tuple)) |idx| {
            self.entries[idx].active = false;
            self.entry_count -= 1;
        }
    }

    /// Evaluate a packet against the connection table.
    /// Returns allow if established/related, no_match if unknown.
    pub fn evaluate(self: *ConnTrack, tuple: Tuple, now_ms: u64) Verdict {
        if (self.lookup(tuple)) |idx| {
            const entry = &self.entries[idx];

            // Check expiry
            if (now_ms > entry.last_seen + entry.timeout) {
                // Expired
                self.entries[idx].active = false;
                self.entry_count -= 1;
                return .no_match;
            }

            return switch (entry.state) {
                .established, .related => .allow,
                .new => .allow,
                .closing => .allow,
                .closed => .deny,
            };
        }
        return .no_match;
    }

    /// Expire timed-out entries. Call periodically.
    pub fn expire(self: *ConnTrack, now_ms: u64) usize {
        var expired: usize = 0;
        for (&self.entries) |*entry| {
            if (!entry.active) continue;
            if (now_ms > entry.last_seen + entry.timeout) {
                entry.active = false;
                self.entry_count -= 1;
                expired += 1;
            }
        }
        return expired;
    }

    /// Set NAT info on an existing connection.
    pub fn setNat(self: *ConnTrack, tuple: Tuple, nat: NatInfo) bool {
        if (self.lookup(tuple)) |idx| {
            self.entries[idx].nat = nat;
            // Update reply tuple for NAT
            if (nat.nat_type == .snat) {
                self.entries[idx].reply.dst_addr = nat.addr;
                self.entries[idx].reply.dst_port = nat.port;
            } else if (nat.nat_type == .dnat) {
                self.entries[idx].reply.src_addr = nat.addr;
                self.entries[idx].reply.src_port = nat.port;
            }
            return true;
        }
        return false;
    }

    /// Get NAT translation for a packet tuple.
    /// Returns the translated address/port if NAT applies.
    pub fn getNat(self: *const ConnTrack, tuple: Tuple) ?NatInfo {
        if (self.lookup(tuple)) |idx| {
            const entry = &self.entries[idx];
            if (entry.nat.nat_type != .none) {
                return entry.nat;
            }
        }
        return null;
    }

    /// Get entry state for a tuple (for inspection/testing).
    pub fn getState(self: *const ConnTrack, tuple: Tuple) ?ConnState {
        if (self.lookup(tuple)) |idx| {
            return self.entries[idx].state;
        }
        return null;
    }

    /// Get per-flow traffic statistics.
    pub fn getStats(self: *const ConnTrack, tuple: Tuple) ?ConnStats {
        if (self.lookup(tuple)) |idx| {
            return self.entries[idx].stats;
        }
        return null;
    }

    /// Get aggregate stats: total bytes across all active flows.
    pub fn totalBytes(self: *const ConnTrack) u64 {
        var total: u64 = 0;
        for (&self.entries) |*entry| {
            if (!entry.active) continue;
            total += entry.stats.bytes_orig + entry.stats.bytes_reply;
        }
        return total;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

const tcp_tuple = Tuple{
    .src_addr = .{ 10, 0, 0, 1 },
    .dst_addr = .{ 192, 168, 1, 1 },
    .src_port = 5000,
    .dst_port = 80,
    .protocol = .tcp,
};

test "conntrack: new connection" {
    var ct = ConnTrack.init();
    const idx = ct.track(tcp_tuple, 1000, false);
    try testing.expect(idx != null);
    try testing.expectEqual(@as(usize, 1), ct.entry_count);
    try testing.expectEqual(ConnState.new, ct.getState(tcp_tuple).?);
}

test "conntrack: established on reply" {
    var ct = ConnTrack.init();
    _ = ct.track(tcp_tuple, 1000, false);

    // Reply packet
    const reply = tcp_tuple.reverse();
    _ = ct.track(reply, 1100, true);

    try testing.expectEqual(ConnState.established, ct.getState(tcp_tuple).?);
}

test "conntrack: lookup by original and reply" {
    var ct = ConnTrack.init();
    _ = ct.track(tcp_tuple, 1000, false);

    try testing.expect(ct.lookup(tcp_tuple) != null);
    try testing.expect(ct.lookup(tcp_tuple.reverse()) != null);
}

test "conntrack: evaluate allows tracked connections" {
    var ct = ConnTrack.init();
    _ = ct.track(tcp_tuple, 1000, false);
    _ = ct.track(tcp_tuple.reverse(), 1100, true);

    const verdict = ct.evaluate(tcp_tuple, 2000);
    try testing.expectEqual(Verdict.allow, verdict);
}

test "conntrack: evaluate returns no_match for unknown" {
    var ct = ConnTrack.init();
    const unknown = Tuple{
        .src_addr = .{ 1, 2, 3, 4 },
        .dst_addr = .{ 5, 6, 7, 8 },
        .src_port = 1234,
        .dst_port = 5678,
        .protocol = .udp,
    };
    const verdict = ct.evaluate(unknown, 1000);
    try testing.expectEqual(Verdict.no_match, verdict);
}

test "conntrack: timeout expiry" {
    var ct = ConnTrack.init();
    _ = ct.track(tcp_tuple, 1000, false);

    // Before timeout: entry exists
    try testing.expectEqual(@as(usize, 1), ct.entry_count);

    // After timeout (tcp_new = 30s)
    const expired = ct.expire(32_000);
    try testing.expectEqual(@as(usize, 1), expired);
    try testing.expectEqual(@as(usize, 0), ct.entry_count);
}

test "conntrack: established has longer timeout" {
    var ct = ConnTrack.init();
    _ = ct.track(tcp_tuple, 1000, false);
    _ = ct.track(tcp_tuple.reverse(), 1100, true);

    // After 30s (tcp_new timeout): should still be alive (tcp_established = 300s)
    const expired = ct.expire(32_000);
    try testing.expectEqual(@as(usize, 0), expired);
    try testing.expectEqual(@as(usize, 1), ct.entry_count);
}

test "conntrack: mark closing" {
    var ct = ConnTrack.init();
    _ = ct.track(tcp_tuple, 1000, false);
    _ = ct.track(tcp_tuple.reverse(), 1100, true);

    ct.markClosing(tcp_tuple, 2000);
    try testing.expectEqual(ConnState.closing, ct.getState(tcp_tuple).?);

    // Closing timeout is 60s
    const e1 = ct.expire(50_000);
    try testing.expectEqual(@as(usize, 0), e1);
    const e2 = ct.expire(63_000);
    try testing.expectEqual(@as(usize, 1), e2);
}

test "conntrack: remove" {
    var ct = ConnTrack.init();
    _ = ct.track(tcp_tuple, 1000, false);
    try testing.expectEqual(@as(usize, 1), ct.entry_count);

    ct.remove(tcp_tuple);
    try testing.expectEqual(@as(usize, 0), ct.entry_count);
    try testing.expect(ct.lookup(tcp_tuple) == null);
}

test "conntrack: SNAT" {
    var ct = ConnTrack.init();
    _ = ct.track(tcp_tuple, 1000, false);

    // Apply SNAT: rewrite src to 1.2.3.4:9000
    try testing.expect(ct.setNat(tcp_tuple, .{
        .nat_type = .snat,
        .addr = .{ 1, 2, 3, 4 },
        .port = 9000,
    }));

    // Check NAT info
    const nat = ct.getNat(tcp_tuple);
    try testing.expect(nat != null);
    try testing.expectEqual(NatType.snat, nat.?.nat_type);
    try testing.expect(std.mem.eql(u8, &nat.?.addr, &[4]u8{ 1, 2, 3, 4 }));
    try testing.expectEqual(@as(u16, 9000), nat.?.port);

    // Reply tuple should be updated
    const idx = ct.lookup(tcp_tuple).?;
    const entry = ct.entries[idx];
    try testing.expect(std.mem.eql(u8, &entry.reply.dst_addr, &[4]u8{ 1, 2, 3, 4 }));
    try testing.expectEqual(@as(u16, 9000), entry.reply.dst_port);
}

test "conntrack: DNAT" {
    var ct = ConnTrack.init();
    const external = Tuple{
        .src_addr = .{ 8, 8, 8, 8 },
        .dst_addr = .{ 1, 2, 3, 4 },
        .src_port = 12345,
        .dst_port = 80,
        .protocol = .tcp,
    };
    _ = ct.track(external, 1000, false);

    // Apply DNAT: forward to internal 10.0.0.100:8080
    try testing.expect(ct.setNat(external, .{
        .nat_type = .dnat,
        .addr = .{ 10, 0, 0, 100 },
        .port = 8080,
    }));

    const idx = ct.lookup(external).?;
    const entry = ct.entries[idx];
    try testing.expect(std.mem.eql(u8, &entry.reply.src_addr, &[4]u8{ 10, 0, 0, 100 }));
    try testing.expectEqual(@as(u16, 8080), entry.reply.src_port);
}

test "conntrack: UDP stream promotion requires bidirectional" {
    var ct = ConnTrack.init();
    const udp_tuple = Tuple{
        .src_addr = .{ 10, 0, 0, 1 },
        .dst_addr = .{ 10, 0, 0, 2 },
        .src_port = 5000,
        .dst_port = 53,
        .protocol = .udp,
    };
    _ = ct.track(udp_tuple, 1000, false);
    _ = ct.track(udp_tuple, 1100, false);
    _ = ct.track(udp_tuple, 1200, false);
    _ = ct.track(udp_tuple, 1300, false);

    // Unidirectional: should expire at 30s (single timeout, not promoted)
    const e1 = ct.expire(32_000);
    try testing.expectEqual(@as(usize, 1), e1);
}

test "conntrack: UDP stream promotion on established" {
    var ct = ConnTrack.init();
    const udp_tuple = Tuple{
        .src_addr = .{ 10, 0, 0, 1 },
        .dst_addr = .{ 10, 0, 0, 2 },
        .src_port = 5000,
        .dst_port = 53,
        .protocol = .udp,
    };
    _ = ct.track(udp_tuple, 1000, false);
    // Reply makes it ESTABLISHED → stream timeout
    _ = ct.track(udp_tuple.reverse(), 1100, true);

    // Should not expire at 30s (stream timeout = 2 min)
    const e1 = ct.expire(32_000);
    try testing.expectEqual(@as(usize, 0), e1);

    // Should expire at 2min+
    const e2 = ct.expire(122_000);
    try testing.expectEqual(@as(usize, 1), e2);
}

test "conntrack: table full returns null" {
    var ct = ConnTrack.init();
    var i: u16 = 0;
    while (i < max_entries) : (i += 1) {
        const t = Tuple{
            .src_addr = .{ 10, 0, @intCast(i >> 8), @intCast(i & 0xff) },
            .dst_addr = .{ 192, 168, 1, 1 },
            .src_port = i,
            .dst_port = 80,
            .protocol = .tcp,
        };
        try testing.expect(ct.track(t, 1000, false) != null);
    }
    // Table full
    const overflow = Tuple{
        .src_addr = .{ 172, 16, 0, 1 },
        .dst_addr = .{ 192, 168, 1, 1 },
        .src_port = 9999,
        .dst_port = 80,
        .protocol = .tcp,
    };
    try testing.expect(ct.track(overflow, 1000, false) == null);
}

test "conntrack: evaluate expires stale on access" {
    var ct = ConnTrack.init();
    _ = ct.track(tcp_tuple, 1000, false);

    // Access after timeout → expired on access
    const verdict = ct.evaluate(tcp_tuple, 50_000);
    try testing.expectEqual(Verdict.no_match, verdict);
    try testing.expectEqual(@as(usize, 0), ct.entry_count);
}

test "conntrack: new unknown tuple with is_reply stays NEW" {
    var ct = ConnTrack.init();
    // Tracking a brand-new tuple with is_reply=true creates it in NEW (not ESTABLISHED)
    _ = ct.track(tcp_tuple, 1000, true);
    try testing.expectEqual(ConnState.new, ct.getState(tcp_tuple).?);
}

test "conntrack: markClosing on NEW state" {
    var ct = ConnTrack.init();
    _ = ct.track(tcp_tuple, 1000, false);
    try testing.expectEqual(ConnState.new, ct.getState(tcp_tuple).?);

    // Can transition directly NEW → CLOSING (RST before handshake completes)
    ct.markClosing(tcp_tuple, 1500);
    try testing.expectEqual(ConnState.closing, ct.getState(tcp_tuple).?);
}

test "conntrack: markClosing is no-op for UDP" {
    var ct = ConnTrack.init();
    const udp_tuple = Tuple{
        .src_addr = .{ 10, 0, 0, 1 },
        .dst_addr = .{ 10, 0, 0, 2 },
        .src_port = 5000,
        .dst_port = 53,
        .protocol = .udp,
    };
    _ = ct.track(udp_tuple, 1000, false);
    ct.markClosing(udp_tuple, 1500);
    // Should remain NEW, not CLOSING
    try testing.expectEqual(ConnState.new, ct.getState(udp_tuple).?);
}

test "conntrack: setNat on unknown tuple returns false" {
    var ct = ConnTrack.init();
    const result = ct.setNat(tcp_tuple, .{
        .nat_type = .snat,
        .addr = .{ 1, 2, 3, 4 },
        .port = 9000,
    });
    try testing.expect(!result);
}

test "conntrack: expire only removes timed-out entries" {
    var ct = ConnTrack.init();
    // Entry 1: short-lived (NEW, 30s timeout)
    _ = ct.track(tcp_tuple, 1000, false);
    // Entry 2: established (5min timeout)
    const long_lived = Tuple{
        .src_addr = .{ 10, 0, 0, 2 },
        .dst_addr = .{ 192, 168, 1, 1 },
        .src_port = 6000,
        .dst_port = 443,
        .protocol = .tcp,
    };
    _ = ct.track(long_lived, 1000, false);
    _ = ct.track(long_lived.reverse(), 1100, true);

    try testing.expectEqual(@as(usize, 2), ct.entry_count);

    // After 35s: only the NEW entry should expire
    const expired = ct.expire(36_000);
    try testing.expectEqual(@as(usize, 1), expired);
    try testing.expectEqual(@as(usize, 1), ct.entry_count);
    try testing.expect(ct.lookup(long_lived) != null);
    try testing.expect(ct.lookup(tcp_tuple) == null);
}

test "conntrack: evaluate closing state allows traffic" {
    var ct = ConnTrack.init();
    _ = ct.track(tcp_tuple, 1000, false);
    _ = ct.track(tcp_tuple.reverse(), 1100, true);
    ct.markClosing(tcp_tuple, 2000);

    // CLOSING state should still allow (FIN-WAIT retransmissions)
    const verdict = ct.evaluate(tcp_tuple, 3000);
    try testing.expectEqual(Verdict.allow, verdict);
}

test "conntrack: stats tracking" {
    var ct = ConnTrack.init();
    _ = ct.trackWithSize(tcp_tuple, 1000, false, 100);
    _ = ct.trackWithSize(tcp_tuple, 1100, false, 200);
    _ = ct.trackWithSize(tcp_tuple.reverse(), 1200, true, 150);

    const stats = ct.getStats(tcp_tuple).?;
    try testing.expectEqual(@as(u32, 2), stats.packets_orig);
    try testing.expectEqual(@as(u64, 300), stats.bytes_orig);
    try testing.expectEqual(@as(u32, 1), stats.packets_reply);
    try testing.expectEqual(@as(u64, 150), stats.bytes_reply);

    try testing.expectEqual(@as(u64, 450), ct.totalBytes());
}
