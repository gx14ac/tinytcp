// FlowTable: NAT/connection tracking table for TCP/UDP flows.
//
// Each flow is identified by a 5-tuple (src_ip, dst_ip, src_port, dst_port, proto)
// and maps to a local endpoint (NAT'd port/address for outbound traffic).
//
// Sans-IO: this module only manages flow state, no I/O.
// Maximum capacity is fixed at comptime for deterministic memory use.

const std = @import("std");

/// 5-tuple flow key.
pub const FlowKey = struct {
    src_addr: [16]u8 = [_]u8{0} ** 16,
    dst_addr: [16]u8 = [_]u8{0} ** 16,
    src_port: u16 = 0,
    dst_port: u16 = 0,
    protocol: u8 = 0,

    /// Create from IPv4 addresses.
    pub fn fromIpv4(src: [4]u8, src_port: u16, dst: [4]u8, dst_port: u16, proto: u8) FlowKey {
        var key = FlowKey{
            .src_port = src_port,
            .dst_port = dst_port,
            .protocol = proto,
        };
        @memcpy(key.src_addr[12..16], &src);
        @memcpy(key.dst_addr[12..16], &dst);
        return key;
    }

    /// Reverse the flow (swap src/dst).
    pub fn reverse(self: FlowKey) FlowKey {
        return FlowKey{
            .src_addr = self.dst_addr,
            .dst_addr = self.src_addr,
            .src_port = self.dst_port,
            .dst_port = self.src_port,
            .protocol = self.protocol,
        };
    }

    /// Hash the flow key.
    pub fn hash(self: *const FlowKey) u64 {
        const bytes = std.mem.asBytes(self);
        return std.hash.Wyhash.hash(0, bytes);
    }

    pub fn eql(a: *const FlowKey, b: *const FlowKey) bool {
        return std.mem.eql(u8, std.mem.asBytes(a), std.mem.asBytes(b));
    }
};

/// Flow state.
pub const FlowState = enum(u8) {
    /// Flow is active.
    active,
    /// Flow is in TIME-WAIT (TCP).
    time_wait,
    /// Flow marked for deletion.
    expired,
};

/// Flow entry stored in the table.
pub const FlowEntry = struct {
    key: FlowKey = .{},
    /// NAT'd local port (for outbound connections).
    nat_port: u16 = 0,
    /// NAT'd local address (for outbound connections).
    nat_addr: [16]u8 = [_]u8{0} ** 16,
    /// State.
    state: FlowState = .active,
    /// Last activity timestamp (ms).
    last_active_ms: u64 = 0,
    /// Whether this entry is occupied.
    occupied: bool = false,
    /// TCP connection index (for TCP flows).
    tcp_conn_idx: ?u16 = null,
};

/// Flow table with fixed capacity.
pub fn FlowTable(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        entries: [capacity]FlowEntry = [_]FlowEntry{.{}} ** capacity,
        count: usize = 0,

        /// TCP idle timeout: 2 hours (RFC 5382).
        const tcp_idle_timeout_ms: u64 = 7200_000;
        /// UDP idle timeout: 30 seconds.
        const udp_idle_timeout_ms: u64 = 30_000;
        /// TIME-WAIT timeout: 120 seconds.
        const time_wait_timeout_ms: u64 = 120_000;

        pub fn init() Self {
            return .{};
        }

        /// Lookup a flow by key. Returns entry pointer or null.
        pub fn lookup(self: *Self, key: *const FlowKey) ?*FlowEntry {
            const h = key.hash();
            var idx = @as(usize, @intCast(h % capacity));
            var probes: usize = 0;

            while (probes < capacity) : (probes += 1) {
                const entry = &self.entries[idx];
                if (!entry.occupied) return null;
                if (entry.key.eql(key)) return entry;
                idx = (idx + 1) % capacity;
            }
            return null;
        }

        /// Insert a new flow. Returns the entry or null if full.
        pub fn insert(self: *Self, key: FlowKey, now_ms: u64) ?*FlowEntry {
            if (self.count >= capacity) return null;

            const h = key.hash();
            var idx = @as(usize, @intCast(h % capacity));
            var probes: usize = 0;

            while (probes < capacity) : (probes += 1) {
                const entry = &self.entries[idx];
                if (!entry.occupied) {
                    entry.* = FlowEntry{
                        .key = key,
                        .state = .active,
                        .last_active_ms = now_ms,
                        .occupied = true,
                    };
                    self.count += 1;
                    return entry;
                }
                idx = (idx + 1) % capacity;
            }
            return null;
        }

        /// Remove a flow by key.
        pub fn remove(self: *Self, key: *const FlowKey) bool {
            const h = key.hash();
            var idx = @as(usize, @intCast(h % capacity));
            var probes: usize = 0;

            while (probes < capacity) : (probes += 1) {
                const entry = &self.entries[idx];
                if (!entry.occupied) return false;
                if (entry.key.eql(key)) {
                    entry.occupied = false;
                    entry.state = .expired;
                    self.count -= 1;
                    // Note: linear probing tombstone handling is simplified here;
                    // a production impl would rehash subsequent entries.
                    return true;
                }
                idx = (idx + 1) % capacity;
            }
            return false;
        }

        /// Touch a flow (update last_active timestamp).
        pub fn touch(self: *Self, key: *const FlowKey, now_ms: u64) void {
            if (self.lookup(key)) |entry| {
                entry.last_active_ms = now_ms;
            }
        }

        /// Expire idle flows. Returns number of entries expired.
        pub fn expireIdle(self: *Self, now_ms: u64) usize {
            var expired: usize = 0;
            for (&self.entries) |*entry| {
                if (!entry.occupied) continue;

                const timeout = switch (entry.state) {
                    .active => blk: {
                        break :blk if (entry.key.protocol == 6)
                            tcp_idle_timeout_ms
                        else
                            udp_idle_timeout_ms;
                    },
                    .time_wait => time_wait_timeout_ms,
                    .expired => 0,
                };

                if (now_ms - entry.last_active_ms >= timeout) {
                    entry.occupied = false;
                    entry.state = .expired;
                    self.count -= 1;
                    expired += 1;
                }
            }
            return expired;
        }

        /// Get the number of active flows.
        pub fn activeCount(self: *const Self) usize {
            return self.count;
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "FlowTable: insert and lookup" {
    var table = FlowTable(64).init();

    const key = FlowKey.fromIpv4(.{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 80, 6);
    const entry = table.insert(key, 100) orelse return error.TestUnexpectedResult;
    entry.nat_port = 40000;

    const found = table.lookup(&key) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u16, 40000), found.nat_port);
    try testing.expectEqual(@as(usize, 1), table.activeCount());
}

test "FlowTable: remove" {
    var table = FlowTable(64).init();

    const key = FlowKey.fromIpv4(.{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 80, 6);
    _ = table.insert(key, 100);
    try testing.expectEqual(@as(usize, 1), table.activeCount());

    try testing.expect(table.remove(&key));
    try testing.expectEqual(@as(usize, 0), table.activeCount());
    try testing.expect(table.lookup(&key) == null);
}

test "FlowTable: expire idle UDP" {
    var table = FlowTable(64).init();

    const key = FlowKey.fromIpv4(.{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 53, 17);
    _ = table.insert(key, 0);

    // Not expired at 29s
    try testing.expectEqual(@as(usize, 0), table.expireIdle(29_000));
    // Expired at 30s
    try testing.expectEqual(@as(usize, 1), table.expireIdle(30_000));
    try testing.expectEqual(@as(usize, 0), table.activeCount());
}

test "FlowTable: TCP flow survives longer" {
    var table = FlowTable(64).init();

    const key = FlowKey.fromIpv4(.{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 80, 6);
    _ = table.insert(key, 0);

    // Not expired at 30s (UDP timeout)
    try testing.expectEqual(@as(usize, 0), table.expireIdle(30_000));
    // Not expired at 1 hour
    try testing.expectEqual(@as(usize, 0), table.expireIdle(3600_000));
    // Expired at 2 hours
    try testing.expectEqual(@as(usize, 1), table.expireIdle(7200_000));
}

test "FlowTable: reverse key" {
    const key = FlowKey.fromIpv4(.{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 80, 6);
    const rev = key.reverse();
    try testing.expectEqual(@as(u16, 80), rev.src_port);
    try testing.expectEqual(@as(u16, 5000), rev.dst_port);
}
