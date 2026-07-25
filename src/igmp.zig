// IGMP — Internet Group Management Protocol (RFC 2236 IGMPv2, RFC 3376 IGMPv3).
//
// Sans-IO: caller drives with timestamps and polls for output packets.
// Supports:
// - Join/Leave group
// - Membership Query handling (General and Group-Specific)
// - Membership Report generation (unsolicited + query response)
// - Group timer management

const std = @import("std");

/// IGMP message types.
pub const MessageType = enum(u8) {
    membership_query = 0x11,
    membership_report_v2 = 0x16,
    leave_group = 0x17,
    membership_report_v3 = 0x22,
    _,
};

/// IGMP output action.
pub const Output = union(enum) {
    none,
    send_report: struct {
        group: [4]u8,
    },
    send_leave: struct {
        group: [4]u8,
    },
};

/// Maximum number of joined multicast groups.
const max_groups: usize = 16;

/// Unsolicited report interval (RFC 2236: 10 seconds max, we use 1s for responsiveness).
const unsolicited_report_interval_ms: u64 = 1000;

/// Number of unsolicited reports to send on join.
const unsolicited_report_count: u8 = 2;

/// Group membership state.
const GroupState = enum {
    idle,
    delay_pending,
};

/// A joined multicast group entry.
pub const GroupEntry = struct {
    addr: [4]u8 = .{ 0, 0, 0, 0 },
    active: bool = false,
    state: GroupState = .idle,
    /// Timer deadline (absolute ms) for delayed report.
    report_deadline: u64 = 0,
    /// Remaining unsolicited reports to send.
    unsolicited_remaining: u8 = 0,
};

/// IGMP state machine.
pub const Igmp = struct {
    groups: [max_groups]GroupEntry = [_]GroupEntry{.{}} ** max_groups,
    group_count: usize = 0,
    /// Robustness variable (IGMPv2 default: 2).
    robustness: u8 = 2,

    /// Join a multicast group. Returns true on success, false if table is full.
    pub fn join(self: *Igmp, group: [4]u8) bool {
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

    /// Leave a multicast group. Returns true if the group was found and removed.
    pub fn leave(self: *Igmp, group: [4]u8) bool {
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
    pub fn isMember(self: *const Igmp, group: [4]u8) bool {
        for (&self.groups) |*entry| {
            if (entry.active and std.mem.eql(u8, &entry.addr, &group)) {
                return true;
            }
        }
        return false;
    }

    /// Process an incoming IGMP packet.
    /// `data` is the raw IGMP message (starts after IP header).
    pub fn onReceive(self: *Igmp, now_ms: u64, data: []const u8) void {
        if (data.len < 8) return;

        const msg_type: MessageType = @enumFromInt(data[0]);
        switch (msg_type) {
            .membership_query => self.handleQuery(now_ms, data),
            .membership_report_v2 => self.handleReport(data),
            else => {},
        }
    }

    /// Poll for pending output. Call periodically (e.g., every tick).
    pub fn poll(self: *Igmp, now_ms: u64) Output {
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

    /// Poll for leave messages. Called after leave() to emit Leave Group message.
    pub fn pollLeave(self: *Igmp, group: [4]u8) Output {
        _ = self;
        return .{ .send_leave = .{ .group = group } };
    }

    /// Serialize a Membership Report (IGMPv2) into a buffer.
    /// Returns the number of bytes written (8 bytes for IGMPv2).
    pub fn buildReport(group: [4]u8, buf: []u8) usize {
        if (buf.len < 8) return 0;
        buf[0] = @intFromEnum(MessageType.membership_report_v2);
        buf[1] = 0; // max resp time (unused in report)
        buf[2] = 0; // checksum (computed below)
        buf[3] = 0;
        buf[4] = group[0];
        buf[5] = group[1];
        buf[6] = group[2];
        buf[7] = group[3];
        // Compute checksum
        const cksum = internetChecksum(buf[0..8]);
        buf[2] = @intCast(cksum >> 8);
        buf[3] = @intCast(cksum & 0xff);
        return 8;
    }

    /// Serialize a Leave Group (IGMPv2) message into a buffer.
    pub fn buildLeave(group: [4]u8, buf: []u8) usize {
        if (buf.len < 8) return 0;
        buf[0] = @intFromEnum(MessageType.leave_group);
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        buf[4] = group[0];
        buf[5] = group[1];
        buf[6] = group[2];
        buf[7] = group[3];
        const cksum = internetChecksum(buf[0..8]);
        buf[2] = @intCast(cksum >> 8);
        buf[3] = @intCast(cksum & 0xff);
        return 8;
    }

    // -- Internal --

    fn handleQuery(self: *Igmp, now_ms: u64, data: []const u8) void {
        // Max Response Time (in 1/10 sec units)
        const max_resp_time = data[1];
        const max_resp_ms: u64 = @as(u64, max_resp_time) * 100;

        // Group address (0.0.0.0 = General Query)
        const query_group = [4]u8{ data[4], data[5], data[6], data[7] };
        const is_general = std.mem.eql(u8, &query_group, &[4]u8{ 0, 0, 0, 0 });

        for (&self.groups) |*entry| {
            if (!entry.active) continue;

            // General query applies to all groups; group-specific only to the target
            if (!is_general and !std.mem.eql(u8, &entry.addr, &query_group)) continue;

            // Set random delay within [0, max_resp_ms]
            // Sans-IO: use deterministic delay (max_resp_ms / 2)
            const delay = if (max_resp_ms > 0) max_resp_ms / 2 else 1;
            const new_deadline = now_ms + delay;

            // Only schedule if no report already pending with an earlier deadline
            if (entry.state == .idle or new_deadline < entry.report_deadline) {
                entry.state = .delay_pending;
                entry.report_deadline = new_deadline;
            }
        }
    }

    fn handleReport(self: *Igmp, data: []const u8) void {
        // Another host reported the same group — cancel our pending report
        const report_group = [4]u8{ data[4], data[5], data[6], data[7] };

        for (&self.groups) |*entry| {
            if (!entry.active) continue;
            if (std.mem.eql(u8, &entry.addr, &report_group)) {
                // Report suppression: cancel our delayed report
                if (entry.state == .delay_pending) {
                    entry.state = .idle;
                }
            }
        }
    }
};

/// One's complement internet checksum (RFC 1071).
fn internetChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u32, data[i]) << 8 | @as(u32, data[i + 1]);
    }
    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~@as(u16, @intCast(sum & 0xffff));
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "IGMP: join and leave" {
    var igmp = Igmp{};

    try testing.expect(igmp.join(.{ 224, 0, 0, 1 }));
    try testing.expect(igmp.isMember(.{ 224, 0, 0, 1 }));
    try testing.expectEqual(@as(usize, 1), igmp.group_count);

    // Duplicate join is idempotent
    try testing.expect(igmp.join(.{ 224, 0, 0, 1 }));
    try testing.expectEqual(@as(usize, 1), igmp.group_count);

    try testing.expect(igmp.leave(.{ 224, 0, 0, 1 }));
    try testing.expect(!igmp.isMember(.{ 224, 0, 0, 1 }));
    try testing.expectEqual(@as(usize, 0), igmp.group_count);
}

test "IGMP: unsolicited reports on join" {
    var igmp = Igmp{};
    _ = igmp.join(.{ 239, 1, 1, 1 });

    // First poll: immediate unsolicited report
    const out1 = igmp.poll(0);
    switch (out1) {
        .send_report => |r| try testing.expect(std.mem.eql(u8, &r.group, &[4]u8{ 239, 1, 1, 1 })),
        else => return error.TestUnexpectedResult,
    }

    // Second poll before deadline: no output
    const out2 = igmp.poll(500);
    switch (out2) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }

    // After interval: second unsolicited report
    const out3 = igmp.poll(1000);
    switch (out3) {
        .send_report => |r| try testing.expect(std.mem.eql(u8, &r.group, &[4]u8{ 239, 1, 1, 1 })),
        else => return error.TestUnexpectedResult,
    }

    // No more unsolicited reports
    const out4 = igmp.poll(3000);
    switch (out4) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
}

test "IGMP: general query triggers delayed report" {
    var igmp = Igmp{};
    _ = igmp.join(.{ 239, 1, 1, 1 });
    // Drain unsolicited reports
    _ = igmp.poll(0);
    _ = igmp.poll(1000);

    // Simulate General Query: type=0x11, max_resp=100 (10s), group=0.0.0.0
    const query = [8]u8{ 0x11, 100, 0, 0, 0, 0, 0, 0 };
    igmp.onReceive(2000, &query);

    // Should not fire immediately
    const out1 = igmp.poll(2000);
    switch (out1) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }

    // After delay (max_resp_ms/2 = 5000ms → deadline=7000)
    const out2 = igmp.poll(7000);
    switch (out2) {
        .send_report => |r| try testing.expect(std.mem.eql(u8, &r.group, &[4]u8{ 239, 1, 1, 1 })),
        else => return error.TestUnexpectedResult,
    }
}

test "IGMP: group-specific query" {
    var igmp = Igmp{};
    _ = igmp.join(.{ 239, 1, 1, 1 });
    _ = igmp.join(.{ 239, 2, 2, 2 });
    _ = igmp.poll(0); // drain unsolicited for group 1
    _ = igmp.poll(0); // drain unsolicited for group 2
    _ = igmp.poll(1000);
    _ = igmp.poll(1000);

    // Group-specific query for 239.1.1.1 only
    const query = [8]u8{ 0x11, 10, 0, 0, 239, 1, 1, 1 }; // max_resp=10 (1s)
    igmp.onReceive(2000, &query);

    // After delay (500ms)
    const out = igmp.poll(2500);
    switch (out) {
        .send_report => |r| try testing.expect(std.mem.eql(u8, &r.group, &[4]u8{ 239, 1, 1, 1 })),
        else => return error.TestUnexpectedResult,
    }

    // Group 2 should not have been triggered
    const out2 = igmp.poll(2500);
    switch (out2) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
}

test "IGMP: report suppression" {
    var igmp = Igmp{};
    _ = igmp.join(.{ 239, 1, 1, 1 });
    _ = igmp.poll(0);
    _ = igmp.poll(1000);

    // Schedule a delayed report via query
    const query = [8]u8{ 0x11, 100, 0, 0, 0, 0, 0, 0 };
    igmp.onReceive(2000, &query);

    // Another host sends a report for the same group
    const report = [8]u8{ 0x16, 0, 0, 0, 239, 1, 1, 1 };
    igmp.onReceive(3000, &report);

    // Our pending report should be suppressed
    const out = igmp.poll(8000);
    switch (out) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
}

test "IGMP: buildReport checksum" {
    var buf: [8]u8 = undefined;
    const len = Igmp.buildReport(.{ 239, 1, 1, 1 }, &buf);
    try testing.expectEqual(@as(usize, 8), len);
    try testing.expectEqual(@as(u8, 0x16), buf[0]); // type

    // Verify checksum: sum of all 16-bit words should be 0xFFFF
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < 8) : (i += 2) {
        sum += @as(u32, buf[i]) << 8 | @as(u32, buf[i + 1]);
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    try testing.expectEqual(@as(u32, 0xffff), sum);
}

test "IGMP: buildLeave" {
    var buf: [8]u8 = undefined;
    const len = Igmp.buildLeave(.{ 239, 5, 5, 5 }, &buf);
    try testing.expectEqual(@as(usize, 8), len);
    try testing.expectEqual(@as(u8, 0x17), buf[0]); // type=leave

    // Verify group address
    try testing.expect(std.mem.eql(u8, buf[4..8], &[4]u8{ 239, 5, 5, 5 }));
}

test "IGMP: table full returns false" {
    var igmp = Igmp{};
    var i: u8 = 0;
    while (i < max_groups) : (i += 1) {
        try testing.expect(igmp.join(.{ 239, 0, 0, i }));
    }
    // Table full
    try testing.expect(!igmp.join(.{ 239, 0, 0, 255 }));
}
