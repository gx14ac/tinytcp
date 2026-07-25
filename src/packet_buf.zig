// PacketBuf: Zero-copy packet buffer with headroom for prepending headers.
//
// Inspired by gVisor's PacketBuffer and Linux sk_buff.
// Each buffer has reserved headroom for lower-layer headers and grows inward.
//
// Layout:
//   [headroom (unused)] [consumed headers] [current data] [tailroom]
//   ^                   ^                  ^              ^
//   buf start           data_start         data_end       buf end

const std = @import("std");

/// Maximum headroom needed: Ethernet(14) + IPv6(40) + TCP(60) = 114, round up.
pub const max_headroom: usize = 128;

/// Default MTU (WireGuard inner payload is typically 1420).
pub const default_mtu: usize = 1420;

/// Total buffer capacity: headroom + MTU.
pub const default_capacity: usize = max_headroom + default_mtu;

/// A packet buffer that supports push (prepend) and consume (strip) operations.
/// Does not own memory — uses externally provided storage (from Pool or stack).
pub const PacketBuf = struct {
    /// Backing storage.
    buf: []u8,

    /// Start of current data within buf.
    data_start: usize,

    /// End of current data within buf (exclusive).
    data_end: usize,

    /// Initialize with external buffer. Data region starts at offset `head_reserve`.
    pub fn init(backing: []u8, head_reserve: usize) PacketBuf {
        return PacketBuf{
            .buf = backing,
            .data_start = head_reserve,
            .data_end = head_reserve,
        };
    }

    /// Initialize with data already placed at a given offset.
    pub fn initWithData(backing: []u8, data_start: usize, data_end: usize) PacketBuf {
        return PacketBuf{
            .buf = backing,
            .data_start = data_start,
            .data_end = data_end,
        };
    }

    /// Current data slice.
    pub fn data(self: *const PacketBuf) []const u8 {
        return self.buf[self.data_start..self.data_end];
    }

    /// Current data as mutable slice.
    pub fn dataMut(self: *PacketBuf) []u8 {
        return self.buf[self.data_start..self.data_end];
    }

    /// Length of current data.
    pub fn len(self: *const PacketBuf) usize {
        return self.data_end - self.data_start;
    }

    /// Available headroom (bytes before data_start).
    pub fn headroom(self: *const PacketBuf) usize {
        return self.data_start;
    }

    /// Available tailroom (bytes after data_end).
    pub fn tailroom(self: *const PacketBuf) usize {
        return self.buf.len - self.data_end;
    }

    /// Prepend `count` bytes to the front (e.g., adding a header).
    /// Returns a mutable slice for the caller to fill.
    pub fn push(self: *PacketBuf, count: usize) error{NoHeadroom}![]u8 {
        if (count > self.data_start) return error.NoHeadroom;
        self.data_start -= count;
        return self.buf[self.data_start .. self.data_start + count];
    }

    /// Remove `count` bytes from the front (e.g., stripping a parsed header).
    /// Returns the consumed slice.
    pub fn consume(self: *PacketBuf, count: usize) error{NotEnoughData}![]const u8 {
        if (count > self.len()) return error.NotEnoughData;
        const consumed = self.buf[self.data_start .. self.data_start + count];
        self.data_start += count;
        return consumed;
    }

    /// Append `count` bytes at the end (e.g., adding payload).
    /// Returns a mutable slice for the caller to fill.
    pub fn append(self: *PacketBuf, count: usize) error{NoTailroom}![]u8 {
        if (count > self.tailroom()) return error.NoTailroom;
        const slice = self.buf[self.data_end .. self.data_end + count];
        self.data_end += count;
        return slice;
    }

    /// Trim `count` bytes from the end.
    pub fn trimEnd(self: *PacketBuf, count: usize) void {
        if (count >= self.len()) {
            self.data_end = self.data_start;
        } else {
            self.data_end -= count;
        }
    }

    /// Reset the buffer (discard all data, restore headroom).
    pub fn reset(self: *PacketBuf, new_headroom: usize) void {
        self.data_start = new_headroom;
        self.data_end = new_headroom;
    }

    /// Copy payload into the buffer at current data_end.
    pub fn appendSlice(self: *PacketBuf, payload: []const u8) error{NoTailroom}!void {
        const dest = try self.append(payload.len);
        @memcpy(dest, payload);
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "PacketBuf: basic push and consume" {
    var backing: [256]u8 = undefined;
    var pb = PacketBuf.init(&backing, 64);

    // Append payload
    try pb.appendSlice("hello");
    try testing.expectEqual(@as(usize, 5), pb.len());
    try testing.expectEqualSlices(u8, "hello", pb.data());

    // Push a 4-byte "header"
    const hdr = try pb.push(4);
    hdr[0] = 0xAA;
    hdr[1] = 0xBB;
    hdr[2] = 0xCC;
    hdr[3] = 0xDD;
    try testing.expectEqual(@as(usize, 9), pb.len());

    // Consume the header
    const consumed = try pb.consume(4);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD }, consumed);
    try testing.expectEqualSlices(u8, "hello", pb.data());
}

test "PacketBuf: push error on no headroom" {
    var backing: [64]u8 = undefined;
    var pb = PacketBuf.init(&backing, 0); // no headroom
    try testing.expectError(error.NoHeadroom, pb.push(1));
}

test "PacketBuf: consume error on empty" {
    var backing: [64]u8 = undefined;
    var pb = PacketBuf.init(&backing, 32);
    try testing.expectError(error.NotEnoughData, pb.consume(1));
}

test "PacketBuf: trim end" {
    var backing: [64]u8 = undefined;
    var pb = PacketBuf.init(&backing, 32);
    try pb.appendSlice("abcdef");
    pb.trimEnd(3);
    try testing.expectEqualSlices(u8, "abc", pb.data());
}

test "PacketBuf: headroom and tailroom" {
    var backing: [256]u8 = undefined;
    var pb = PacketBuf.init(&backing, max_headroom);
    try testing.expectEqual(max_headroom, pb.headroom());
    try testing.expectEqual(@as(usize, 256 - max_headroom), pb.tailroom());
}
