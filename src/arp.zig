// ARP (Address Resolution Protocol, RFC 826).
//
// Maintains an IPv4 → MAC address mapping table and handles ARP request/reply.
// Used when the stack operates over Ethernet (L2 mode) rather than raw IP (L3/TUN mode).
//
// Features:
// - Static and dynamic entries
// - Configurable entry timeout (default 300s)
// - ARP request generation and reply handling
// - Gratuitous ARP support
//
// Sans-IO: produces ARP packets as byte slices; caller sends them.

const std = @import("std");

/// Maximum ARP table entries.
const max_entries: usize = 64;

/// ARP entry timeout (ms).
const entry_timeout_ms: u64 = 300_000;

/// ARP hardware type: Ethernet.
const hw_type_ethernet: u16 = 1;

/// ARP opcodes.
pub const Opcode = enum(u16) {
    request = 1,
    reply = 2,
    _,
};

/// ARP table entry.
pub const Entry = struct {
    ip: [4]u8 = .{0} ** 4,
    mac: [6]u8 = .{0} ** 6,
    active: bool = false,
    static: bool = false,
    created_ms: u64 = 0,
};

/// Parsed ARP packet (Ethernet/IPv4).
pub const ArpPacket = struct {
    hw_type: u16,
    proto_type: u16,
    hw_len: u8,
    proto_len: u8,
    opcode: Opcode,
    sender_mac: [6]u8,
    sender_ip: [4]u8,
    target_mac: [6]u8,
    target_ip: [4]u8,

    pub fn parse(data: []const u8) ?ArpPacket {
        if (data.len < 28) return null;
        return ArpPacket{
            .hw_type = std.mem.readInt(u16, data[0..2], .big),
            .proto_type = std.mem.readInt(u16, data[2..4], .big),
            .hw_len = data[4],
            .proto_len = data[5],
            .opcode = @enumFromInt(std.mem.readInt(u16, data[6..8], .big)),
            .sender_mac = data[8..14].*,
            .sender_ip = data[14..18].*,
            .target_mac = data[18..24].*,
            .target_ip = data[24..28].*,
        };
    }

    pub fn serialize(self: *const ArpPacket, out: []u8) usize {
        if (out.len < 28) return 0;
        std.mem.writeInt(u16, out[0..2], self.hw_type, .big);
        std.mem.writeInt(u16, out[2..4], self.proto_type, .big);
        out[4] = self.hw_len;
        out[5] = self.proto_len;
        std.mem.writeInt(u16, out[6..8], @intFromEnum(self.opcode), .big);
        @memcpy(out[8..14], &self.sender_mac);
        @memcpy(out[14..18], &self.sender_ip);
        @memcpy(out[18..24], &self.target_mac);
        @memcpy(out[24..28], &self.target_ip);
        return 28;
    }
};

/// ARP output action.
pub const ArpAction = union(enum) {
    none,
    /// Send this ARP packet.
    send: [28]u8,
};

/// ARP table and protocol handler.
pub const ArpTable = struct {
    entries: [max_entries]Entry = [_]Entry{.{}} ** max_entries,
    local_ip: [4]u8 = .{0} ** 4,
    local_mac: [6]u8 = .{0} ** 6,

    pub fn init(local_ip: [4]u8, local_mac: [6]u8) ArpTable {
        return .{ .local_ip = local_ip, .local_mac = local_mac };
    }

    /// Look up MAC for an IP address. Returns null if not found.
    pub fn lookup(self: *const ArpTable, ip: [4]u8) ?[6]u8 {
        for (&self.entries) |*e| {
            if (e.active and std.mem.eql(u8, &e.ip, &ip)) return e.mac;
        }
        return null;
    }

    /// Insert or update an entry.
    pub fn insert(self: *ArpTable, now_ms: u64, ip: [4]u8, mac: [6]u8) void {
        // Update existing
        for (&self.entries) |*e| {
            if (e.active and std.mem.eql(u8, &e.ip, &ip)) {
                e.mac = mac;
                e.created_ms = now_ms;
                return;
            }
        }
        // Find empty slot
        for (&self.entries) |*e| {
            if (!e.active) {
                e.* = .{ .ip = ip, .mac = mac, .active = true, .created_ms = now_ms };
                return;
            }
        }
        // Evict oldest non-static
        var oldest_idx: ?usize = null;
        var oldest_ts: u64 = std.math.maxInt(u64);
        for (&self.entries, 0..) |*e, i| {
            if (!e.static and e.created_ms < oldest_ts) {
                oldest_ts = e.created_ms;
                oldest_idx = i;
            }
        }
        if (oldest_idx) |idx| {
            self.entries[idx] = .{ .ip = ip, .mac = mac, .active = true, .created_ms = now_ms };
        }
    }

    /// Add a static entry (never expires).
    pub fn insertStatic(self: *ArpTable, ip: [4]u8, mac: [6]u8) void {
        for (&self.entries) |*e| {
            if (e.active and std.mem.eql(u8, &e.ip, &ip)) {
                e.mac = mac;
                e.static = true;
                return;
            }
        }
        for (&self.entries) |*e| {
            if (!e.active) {
                e.* = .{ .ip = ip, .mac = mac, .active = true, .static = true };
                return;
            }
        }
    }

    /// Handle an incoming ARP packet.
    /// Returns an action (reply or none).
    pub fn onPacket(self: *ArpTable, now_ms: u64, data: []const u8) ArpAction {
        const pkt = ArpPacket.parse(data) orelse return .none;
        if (pkt.hw_type != hw_type_ethernet or pkt.proto_type != 0x0800) return .none;
        if (pkt.hw_len != 6 or pkt.proto_len != 4) return .none;

        // Learn sender's mapping
        self.insert(now_ms, pkt.sender_ip, pkt.sender_mac);

        switch (pkt.opcode) {
            .request => {
                // If they're asking for our IP, send reply
                if (std.mem.eql(u8, &pkt.target_ip, &self.local_ip)) {
                    var reply = ArpPacket{
                        .hw_type = hw_type_ethernet,
                        .proto_type = 0x0800,
                        .hw_len = 6,
                        .proto_len = 4,
                        .opcode = .reply,
                        .sender_mac = self.local_mac,
                        .sender_ip = self.local_ip,
                        .target_mac = pkt.sender_mac,
                        .target_ip = pkt.sender_ip,
                    };
                    var buf: [28]u8 = undefined;
                    _ = reply.serialize(&buf);
                    return .{ .send = buf };
                }
                return .none;
            },
            .reply => {
                // Already learned above
                return .none;
            },
            _ => return .none,
        }
    }

    /// Generate an ARP request for an IP address.
    pub fn makeRequest(self: *const ArpTable, target_ip: [4]u8) [28]u8 {
        var req = ArpPacket{
            .hw_type = hw_type_ethernet,
            .proto_type = 0x0800,
            .hw_len = 6,
            .proto_len = 4,
            .opcode = .request,
            .sender_mac = self.local_mac,
            .sender_ip = self.local_ip,
            .target_mac = .{0} ** 6,
            .target_ip = target_ip,
        };
        var buf: [28]u8 = undefined;
        _ = req.serialize(&buf);
        return buf;
    }

    /// Generate a gratuitous ARP (announce our address).
    pub fn makeGratuitous(self: *const ArpTable) [28]u8 {
        var garp = ArpPacket{
            .hw_type = hw_type_ethernet,
            .proto_type = 0x0800,
            .hw_len = 6,
            .proto_len = 4,
            .opcode = .request,
            .sender_mac = self.local_mac,
            .sender_ip = self.local_ip,
            .target_mac = .{0xFF} ** 6,
            .target_ip = self.local_ip,
        };
        var buf: [28]u8 = undefined;
        _ = garp.serialize(&buf);
        return buf;
    }

    /// Expire old entries.
    pub fn tick(self: *ArpTable, now_ms: u64) void {
        for (&self.entries) |*e| {
            if (e.active and !e.static and now_ms >= e.created_ms + entry_timeout_ms) {
                e.active = false;
            }
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "ArpTable: insert and lookup" {
    var table = ArpTable.init(.{ 10, 0, 0, 1 }, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF });
    table.insert(0, .{ 10, 0, 0, 2 }, .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 });

    const mac = table.lookup(.{ 10, 0, 0, 2 });
    try testing.expect(mac != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, &mac.?);

    // Unknown IP
    try testing.expect(table.lookup(.{ 10, 0, 0, 3 }) == null);
}

test "ArpTable: handle request and reply" {
    var table = ArpTable.init(.{ 192, 168, 1, 1 }, .{ 0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03 });

    // Build ARP request: "Who has 192.168.1.1?"
    const req = ArpPacket{
        .hw_type = hw_type_ethernet,
        .proto_type = 0x0800,
        .hw_len = 6,
        .proto_len = 4,
        .opcode = .request,
        .sender_mac = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
        .sender_ip = .{ 192, 168, 1, 2 },
        .target_mac = .{0} ** 6,
        .target_ip = .{ 192, 168, 1, 1 },
    };
    var buf: [28]u8 = undefined;
    _ = req.serialize(&buf);

    const action = table.onPacket(100, &buf);
    switch (action) {
        .send => |reply_buf| {
            const reply = ArpPacket.parse(&reply_buf).?;
            try testing.expectEqual(Opcode.reply, reply.opcode);
            try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03 }, &reply.sender_mac);
            try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, &reply.sender_ip);
            try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 2 }, &reply.target_ip);
        },
        .none => return error.TestUnexpectedResult,
    }

    // Sender should have been learned
    const learned = table.lookup(.{ 192, 168, 1, 2 });
    try testing.expect(learned != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, &learned.?);
}

test "ArpTable: request for non-local IP returns none" {
    var table = ArpTable.init(.{ 192, 168, 1, 1 }, .{ 0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03 });

    const req = ArpPacket{
        .hw_type = hw_type_ethernet,
        .proto_type = 0x0800,
        .hw_len = 6,
        .proto_len = 4,
        .opcode = .request,
        .sender_mac = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
        .sender_ip = .{ 192, 168, 1, 2 },
        .target_mac = .{0} ** 6,
        .target_ip = .{ 192, 168, 1, 99 }, // not our IP
    };
    var buf: [28]u8 = undefined;
    _ = req.serialize(&buf);

    const action = table.onPacket(0, &buf);
    switch (action) {
        .none => {},
        .send => return error.TestUnexpectedResult,
    }
}

test "ArpTable: static entry doesn't expire" {
    var table = ArpTable.init(.{ 10, 0, 0, 1 }, .{0} ** 6);
    table.insertStatic(.{ 10, 0, 0, 254 }, .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 });

    // Tick past timeout
    table.tick(entry_timeout_ms + 1);

    // Static entry still there
    try testing.expect(table.lookup(.{ 10, 0, 0, 254 }) != null);
}

test "ArpTable: dynamic entry expires" {
    var table = ArpTable.init(.{ 10, 0, 0, 1 }, .{0} ** 6);
    table.insert(0, .{ 10, 0, 0, 2 }, .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 });

    try testing.expect(table.lookup(.{ 10, 0, 0, 2 }) != null);
    table.tick(entry_timeout_ms + 1);
    try testing.expect(table.lookup(.{ 10, 0, 0, 2 }) == null);
}

test "ArpTable: makeRequest" {
    const table = ArpTable.init(.{ 10, 0, 0, 1 }, .{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 });
    const req_buf = table.makeRequest(.{ 10, 0, 0, 2 });
    const pkt = ArpPacket.parse(&req_buf).?;
    try testing.expectEqual(Opcode.request, pkt.opcode);
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 1 }, &pkt.sender_ip);
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 2 }, &pkt.target_ip);
}
