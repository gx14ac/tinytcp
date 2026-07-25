// MLD — Multicast Listener Discovery for IPv6 (RFC 2710 MLDv1, RFC 3810 MLDv2).
//
// Sans-IO: caller drives with timestamps and polls for output packets.
// MLD uses ICMPv6 message types:
// - 130: Multicast Listener Query
// - 131: Multicast Listener Report (MLDv1)
// - 132: Multicast Listener Done (MLDv1)
// - 143: MLDv2 Multicast Listener Report
//
// Supports:
// - Join/Leave multicast group
// - Multicast Listener Query handling (General and Multicast-Address-Specific)
// - Report generation (unsolicited + query response)
// - Report suppression (MLDv1 compatibility)
// - Done message generation on leave

const std = @import("std");

/// MLD/ICMPv6 message types.
pub const MessageType = enum(u8) {
    multicast_listener_query = 130,
    multicast_listener_report_v1 = 131,
    multicast_listener_done = 132,
    multicast_listener_report_v2 = 143,
    _,
};

/// MLD output action.
pub const Output = union(enum) {
    none,
    /// Send a Multicast Listener Report for the given group.
    send_report: struct {
        group: [16]u8,
    },
    /// Send a Multicast Listener Done for the given group.
    send_done: struct {
        group: [16]u8,
    },
};

/// Maximum number of joined multicast groups.
const max_groups: usize = 16;

/// Unsolicited report interval (RFC 2710: default 1 second).
const unsolicited_report_interval_ms: u64 = 1000;

/// Number of unsolicited reports to send on join (Robustness Variable, default 2).
const unsolicited_report_count: u8 = 2;

/// Group listener state.
const ListenerState = enum {
    idle,
    delay_pending,
};

/// A joined IPv6 multicast group entry.
pub const GroupEntry = struct {
    addr: [16]u8 = .{0} ** 16,
    active: bool = false,
    state: ListenerState = .idle,
    report_deadline: u64 = 0,
    unsolicited_remaining: u8 = 0,
};

/// MLD state machine.
pub const Mld = struct {
    groups: [max_groups]GroupEntry = [_]GroupEntry{.{}} ** max_groups,
    group_count: usize = 0,

    /// Join an IPv6 multicast group. Returns true on success.
    pub fn join(self: *Mld, group: [16]u8) bool {
        // Check if already joined
        for (&self.groups) |*entry| {
            if (entry.active and std.mem.eql(u8, &entry.addr, &group)) {
                return true;
            }
        }
        // Find free slot
        for (&self.groups) |*entry| {
            if (!entry.active) {
                entry.* = .{
                    .addr = group,
                    .active = true,
                    .state = .delay_pending,
                    .report_deadline = 0,
                    .unsolicited_remaining = unsolicited_report_count,
                };
                self.group_count += 1;
                return true;
            }
        }
        return false;
    }

    /// Leave an IPv6 multicast group. Returns true if found and removed.
    pub fn leave(self: *Mld, group: [16]u8) bool {
        for (&self.groups) |*entry| {
            if (entry.active and std.mem.eql(u8, &entry.addr, &group)) {
                entry.active = false;
                self.group_count -= 1;
                return true;
            }
        }
        return false;
    }

    /// Check if a group is currently joined.
    pub fn isMember(self: *const Mld, group: [16]u8) bool {
        for (&self.groups) |*entry| {
            if (entry.active and std.mem.eql(u8, &entry.addr, &group)) {
                return true;
            }
        }
        return false;
    }

    /// Process an incoming MLD message (ICMPv6 payload after type/code/checksum).
    /// `data` starts at the ICMPv6 type byte.
    pub fn onReceive(self: *Mld, now_ms: u64, data: []const u8) void {
        if (data.len < 24) return; // MLD minimum: 8 (ICMPv6 header) + 16 (group)

        const msg_type: MessageType = @enumFromInt(data[0]);
        switch (msg_type) {
            .multicast_listener_query => self.handleQuery(now_ms, data),
            .multicast_listener_report_v1 => self.handleReport(data),
            else => {},
        }
    }

    /// Poll for pending output. Returns one action per call.
    pub fn poll(self: *Mld, now_ms: u64) Output {
        for (&self.groups) |*entry| {
            if (!entry.active) continue;

            // Unsolicited reports on join
            if (entry.unsolicited_remaining > 0) {
                if (entry.report_deadline == 0 or now_ms >= entry.report_deadline) {
                    entry.unsolicited_remaining -= 1;
                    entry.report_deadline = now_ms + unsolicited_report_interval_ms;
                    if (entry.unsolicited_remaining == 0) {
                        entry.state = .idle;
                    }
                    return .{ .send_report = .{ .group = entry.addr } };
                }
                continue;
            }

            // Delayed report in response to query
            if (entry.state == .delay_pending and now_ms >= entry.report_deadline) {
                entry.state = .idle;
                return .{ .send_report = .{ .group = entry.addr } };
            }
        }
        return .none;
    }

    /// Build a Done message output for a group that was just left.
    pub fn pollDone(_: *Mld, group: [16]u8) Output {
        return .{ .send_done = .{ .group = group } };
    }

    /// Serialize an MLDv1 Multicast Listener Report into a buffer.
    /// Layout: type(1) + code(1) + checksum(2) + max_resp(2) + reserved(2) + group(16) = 24 bytes.
    /// Checksum must be computed over the pseudo-header externally; we zero it here.
    pub fn buildReport(group: [16]u8, buf: []u8) usize {
        if (buf.len < 24) return 0;
        buf[0] = @intFromEnum(MessageType.multicast_listener_report_v1);
        buf[1] = 0; // code
        buf[2] = 0; // checksum (set by caller with pseudo-header)
        buf[3] = 0;
        buf[4] = 0; // max response delay
        buf[5] = 0;
        buf[6] = 0; // reserved
        buf[7] = 0;
        @memcpy(buf[8..24], &group);
        return 24;
    }

    /// Serialize an MLDv1 Multicast Listener Done message.
    pub fn buildDone(group: [16]u8, buf: []u8) usize {
        if (buf.len < 24) return 0;
        buf[0] = @intFromEnum(MessageType.multicast_listener_done);
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        buf[4] = 0;
        buf[5] = 0;
        buf[6] = 0;
        buf[7] = 0;
        @memcpy(buf[8..24], &group);
        return 24;
    }

    // -- Internal --

    fn handleQuery(self: *Mld, now_ms: u64, data: []const u8) void {
        // Maximum Response Delay (ms) — bytes 4-5, big-endian
        const max_resp_ms: u64 = @as(u64, data[4]) << 8 | @as(u64, data[5]);

        // Multicast Address field (bytes 8-23). All-zeros = General Query.
        var query_group: [16]u8 = .{0} ** 16;
        @memcpy(&query_group, data[8..24]);
        const is_general = std.mem.eql(u8, &query_group, &([_]u8{0} ** 16));

        for (&self.groups) |*entry| {
            if (!entry.active) continue;

            if (!is_general and !std.mem.eql(u8, &entry.addr, &query_group)) continue;

            // Deterministic delay: max_resp_ms / 2
            const delay = if (max_resp_ms > 0) max_resp_ms / 2 else 1;
            const new_deadline = now_ms + delay;

            if (entry.state == .idle or new_deadline < entry.report_deadline) {
                entry.state = .delay_pending;
                entry.report_deadline = new_deadline;
            }
        }
    }

    fn handleReport(self: *Mld, data: []const u8) void {
        // Report suppression: cancel delayed report for the same group
        if (data.len < 24) return;
        var report_group: [16]u8 = .{0} ** 16;
        @memcpy(&report_group, data[8..24]);

        for (&self.groups) |*entry| {
            if (!entry.active) continue;
            if (std.mem.eql(u8, &entry.addr, &report_group)) {
                if (entry.state == .delay_pending) {
                    entry.state = .idle;
                }
            }
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

const ff02_1 = [16]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const ff02_fb = [16]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb };

test "MLD: join and leave" {
    var mld = Mld{};

    try testing.expect(mld.join(ff02_1));
    try testing.expect(mld.isMember(ff02_1));
    try testing.expectEqual(@as(usize, 1), mld.group_count);

    // Duplicate join is idempotent
    try testing.expect(mld.join(ff02_1));
    try testing.expectEqual(@as(usize, 1), mld.group_count);

    try testing.expect(mld.leave(ff02_1));
    try testing.expect(!mld.isMember(ff02_1));
    try testing.expectEqual(@as(usize, 0), mld.group_count);
}

test "MLD: unsolicited reports on join" {
    var mld = Mld{};
    _ = mld.join(ff02_fb);

    // First poll: immediate unsolicited report
    const out1 = mld.poll(0);
    switch (out1) {
        .send_report => |r| try testing.expect(std.mem.eql(u8, &r.group, &ff02_fb)),
        else => return error.TestUnexpectedResult,
    }

    // Before interval: no output
    const out2 = mld.poll(500);
    switch (out2) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }

    // After interval: second unsolicited report
    const out3 = mld.poll(1000);
    switch (out3) {
        .send_report => |r| try testing.expect(std.mem.eql(u8, &r.group, &ff02_fb)),
        else => return error.TestUnexpectedResult,
    }

    // No more
    const out4 = mld.poll(3000);
    switch (out4) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
}

test "MLD: general query triggers delayed report" {
    var mld = Mld{};
    _ = mld.join(ff02_fb);
    // Drain unsolicited
    _ = mld.poll(0);
    _ = mld.poll(1000);

    // General Query: type=130, code=0, cksum=0, max_resp=1000ms (0x03E8), reserved=0, group=::
    var query: [24]u8 = .{0} ** 24;
    query[0] = 130; // type
    query[4] = 0x03; // max_resp_ms high
    query[5] = 0xE8; // max_resp_ms low = 1000

    mld.onReceive(2000, &query);

    // Should not fire immediately
    const out1 = mld.poll(2000);
    switch (out1) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }

    // After delay (1000/2 = 500ms → deadline=2500)
    const out2 = mld.poll(2500);
    switch (out2) {
        .send_report => |r| try testing.expect(std.mem.eql(u8, &r.group, &ff02_fb)),
        else => return error.TestUnexpectedResult,
    }
}

test "MLD: multicast-address-specific query" {
    var mld = Mld{};
    _ = mld.join(ff02_1);
    _ = mld.join(ff02_fb);
    // Drain unsolicited for both
    _ = mld.poll(0);
    _ = mld.poll(0);
    _ = mld.poll(1000);
    _ = mld.poll(1000);

    // Query for ff02::fb only
    var query: [24]u8 = .{0} ** 24;
    query[0] = 130;
    query[4] = 0;
    query[5] = 100; // 100ms max resp
    @memcpy(query[8..24], &ff02_fb);

    mld.onReceive(2000, &query);

    // After delay (50ms)
    const out = mld.poll(2050);
    switch (out) {
        .send_report => |r| try testing.expect(std.mem.eql(u8, &r.group, &ff02_fb)),
        else => return error.TestUnexpectedResult,
    }

    // ff02::1 should not have been triggered
    const out2 = mld.poll(2050);
    switch (out2) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
}

test "MLD: report suppression" {
    var mld = Mld{};
    _ = mld.join(ff02_fb);
    _ = mld.poll(0);
    _ = mld.poll(1000);

    // Schedule delayed report via query
    var query: [24]u8 = .{0} ** 24;
    query[0] = 130;
    query[4] = 0x03;
    query[5] = 0xE8;
    mld.onReceive(2000, &query);

    // Another host sends report for same group
    var report: [24]u8 = .{0} ** 24;
    report[0] = 131; // MLDv1 Report
    @memcpy(report[8..24], &ff02_fb);
    mld.onReceive(2200, &report);

    // Our delayed report should be suppressed
    const out = mld.poll(5000);
    switch (out) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
}

test "MLD: buildReport" {
    var buf: [24]u8 = undefined;
    const len = Mld.buildReport(ff02_fb, &buf);
    try testing.expectEqual(@as(usize, 24), len);
    try testing.expectEqual(@as(u8, 131), buf[0]);
    try testing.expect(std.mem.eql(u8, buf[8..24], &ff02_fb));
}

test "MLD: buildDone" {
    var buf: [24]u8 = undefined;
    const len = Mld.buildDone(ff02_1, &buf);
    try testing.expectEqual(@as(usize, 24), len);
    try testing.expectEqual(@as(u8, 132), buf[0]);
    try testing.expect(std.mem.eql(u8, buf[8..24], &ff02_1));
}

test "MLD: table full returns false" {
    var mld = Mld{};
    var i: u8 = 0;
    while (i < max_groups) : (i += 1) {
        var addr: [16]u8 = .{0} ** 16;
        addr[0] = 0xff;
        addr[1] = 0x02;
        addr[15] = i;
        try testing.expect(mld.join(addr));
    }
    var overflow_addr: [16]u8 = .{0} ** 16;
    overflow_addr[0] = 0xff;
    overflow_addr[15] = 0xff;
    try testing.expect(!mld.join(overflow_addr));
}
