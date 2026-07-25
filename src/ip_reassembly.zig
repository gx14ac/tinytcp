// IPv4 Fragment Reassembly (RFC 791, RFC 815).
//
// Reassembles fragmented IPv4 packets by tracking fragments per (src, dst, id, proto).
// Uses a fixed-size buffer pool to avoid dynamic allocation.
//
// Limits:
// - Max 8 concurrent reassembly flows
// - Max 65535 bytes per reassembled datagram
// - 30-second timeout per flow (RFC 791: "first fragment timer")
//
// Sans-IO: caller drives with injectFragment(), no timers or I/O.

const std = @import("std");
const ipv4_header = @import("header/ipv4.zig");

/// Default reassembly parameters.
pub const default_max_flows: usize = 8;
pub const default_max_datagram: usize = 8192;

/// Reassembly timeout (ms).
const reassembly_timeout_ms: u64 = 30_000;

/// Legacy aliases for backwards compatibility.
const max_flows = default_max_flows;
const max_datagram = default_max_datagram;

/// Fragment flow key.
const FlowKey = struct {
    src: [4]u8,
    dst: [4]u8,
    id: u16,
    proto: u8,

    fn eql(a: FlowKey, b: FlowKey) bool {
        return std.mem.eql(u8, &a.src, &b.src) and
            std.mem.eql(u8, &a.dst, &b.dst) and
            a.id == b.id and a.proto == b.proto;
    }
};

/// Default reassembler (8 flows, 8192 bytes per datagram).
pub const Reassembler = ReassemblerWith(default_max_flows, default_max_datagram);

/// Parameterized reassembler for embedded targets with limited stack/RAM.
pub fn ReassemblerWith(comptime flows: usize, comptime datagram_size: usize) type {
    const bitmap_bytes = (datagram_size + 63) / 64;

    const Slot = struct {
        key: FlowKey = undefined,
        active: bool = false,
        buf: [datagram_size]u8 = undefined,
        received: [bitmap_bytes]u8 = .{0} ** bitmap_bytes,
        total_len: u16 = 0,
        first_frag_ts: u64 = 0,
        bytes_received: u16 = 0,
        last_seen: bool = false,
        ip_hdr_len: u8 = 20,

        fn reset(self: *@This()) void {
            self.active = false;
            @memset(&self.received, 0);
            self.total_len = 0;
            self.bytes_received = 0;
            self.last_seen = false;
        }

        fn markRange(self: *@This(), offset: u16, len: u16) void {
            const start_block = offset / 8;
            const end_block = (offset + len + 7) / 8;
            var b: u16 = start_block;
            while (b < end_block and b < datagram_size / 8) : (b += 1) {
                const byte_idx = b / 8;
                const bit_idx: u3 = @truncate(b % 8);
                if (byte_idx < bitmap_bytes) {
                    self.received[byte_idx] |= @as(u8, 1) << bit_idx;
                }
            }
        }

        fn isComplete(self: *const @This()) bool {
            if (!self.last_seen or self.total_len == 0) return false;
            const total_blocks = (self.total_len + 7) / 8;
            var b: u16 = 0;
            while (b < total_blocks) : (b += 1) {
                const byte_idx = b / 8;
                const bit_idx: u3 = @truncate(b % 8);
                if (byte_idx >= bitmap_bytes) return false;
                if (self.received[byte_idx] & (@as(u8, 1) << bit_idx) == 0) return false;
            }
            return true;
        }
    };

    return struct {
        const Self = @This();
        pub const max_datagram_size = datagram_size;

        slots: [flows]Slot = [_]Slot{.{}} ** flows,

        pub fn inject(self: *Self, now_ms: u64, raw: []const u8) ?struct { data: []const u8, slot_idx: usize } {
            if (raw.len < 20) return null;
            const ip_hdr = ipv4_header.Header.parse(raw) catch return null;

            const frag_offset = ip_hdr.fragmentOffset();
            const more_frags = ip_hdr.moreFragments();

            if (frag_offset == 0 and !more_frags) return null;

            const key = FlowKey{
                .src = ip_hdr.srcAddr(),
                .dst = ip_hdr.dstAddr(),
                .id = ip_hdr.identification(),
                .proto = @intFromEnum(ip_hdr.protocol()),
            };

            const slot_idx = self.findOrAlloc(now_ms, key) orelse return null;
            const slot = &self.slots[slot_idx];

            const payload = ip_hdr.payload(raw);
            const byte_offset = @as(u16, frag_offset) * 8;

            if (@as(usize, byte_offset) + payload.len > datagram_size) return null;
            @memcpy(slot.buf[byte_offset .. byte_offset + payload.len], payload);
            slot.markRange(byte_offset, @intCast(payload.len));
            slot.bytes_received += @intCast(payload.len);

            if (!more_frags) {
                slot.last_seen = true;
                slot.total_len = byte_offset + @as(u16, @intCast(payload.len));
            }

            if (frag_offset == 0) {
                slot.ip_hdr_len = @intCast(ip_hdr.headerLen());
            }

            if (slot.isComplete()) {
                return .{ .data = slot.buf[0..slot.total_len], .slot_idx = slot_idx };
            }

            return null;
        }

        pub fn release(self: *Self, slot_idx: usize) void {
            if (slot_idx < flows) {
                self.slots[slot_idx].reset();
            }
        }

        pub fn tick(self: *Self, now_ms: u64) void {
            for (&self.slots) |*slot| {
                if (slot.active and now_ms >= slot.first_frag_ts + reassembly_timeout_ms) {
                    slot.reset();
                }
            }
        }

        fn findOrAlloc(self: *Self, now_ms: u64, key: FlowKey) ?usize {
            for (&self.slots, 0..) |*slot, i| {
                if (slot.active and FlowKey.eql(slot.key, key)) return i;
            }
            var oldest_idx: ?usize = null;
            var oldest_ts: u64 = std.math.maxInt(u64);
            for (&self.slots, 0..) |*slot, i| {
                if (!slot.active) {
                    slot.* = .{};
                    slot.active = true;
                    slot.key = key;
                    slot.first_frag_ts = now_ms;
                    return i;
                }
                if (slot.first_frag_ts < oldest_ts) {
                    oldest_ts = slot.first_frag_ts;
                    oldest_idx = i;
                }
            }
            if (oldest_idx) |idx| {
                self.slots[idx].reset();
                self.slots[idx].active = true;
                self.slots[idx].key = key;
                self.slots[idx].first_frag_ts = now_ms;
                return idx;
            }
            return null;
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn buildFragment(src: [4]u8, dst: [4]u8, id: u16, offset: u13, more_frags: bool, payload: []const u8, out: []u8) usize {
    const ip_hlen: usize = 20;
    const total: usize = ip_hlen + payload.len;
    var ip = ipv4_header.MutableHeader.init(out[0..ip_hlen]) catch unreachable;
    ip.setTotalLen(@intCast(total));
    ip.setIdentification(id);
    ip.setTtl(64);
    ip.setProtocol(.tcp);
    ip.setSrcAddr(src);
    ip.setDstAddr(dst);
    // Set fragment offset and MF flag
    const frag_word: u16 = (@as(u16, offset) & 0x1FFF) | (if (more_frags) @as(u16, 0x2000) else 0);
    out[6] = @intCast(frag_word >> 8);
    out[7] = @intCast(frag_word & 0xFF);
    ip.computeChecksum();
    @memcpy(out[ip_hlen .. ip_hlen + payload.len], payload);
    return total;
}

test "Reassembler: two-fragment reassembly" {
    var ra = Reassembler{};

    var buf1: [128]u8 = undefined;
    var buf2: [128]u8 = undefined;

    // Fragment 1: offset=0, MF=1, 16 bytes payload
    const payload1 = "0123456789ABCDEF";
    const len1 = buildFragment(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, 100, 0, true, payload1, &buf1);

    // Fragment 2: offset=2 (16 bytes / 8 = 2), MF=0, 8 bytes payload
    const payload2 = "GHIJKLMN";
    const len2 = buildFragment(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, 100, 2, false, payload2, &buf2);

    // Inject fragment 1 — not complete yet
    const r1 = ra.inject(0, buf1[0..len1]);
    try testing.expect(r1 == null);

    // Inject fragment 2 — should complete
    const r2 = ra.inject(0, buf2[0..len2]);
    try testing.expect(r2 != null);
    try testing.expectEqual(@as(usize, 24), r2.?.data.len);
    try testing.expectEqualSlices(u8, "0123456789ABCDEF", r2.?.data[0..16]);
    try testing.expectEqualSlices(u8, "GHIJKLMN", r2.?.data[16..24]);

    ra.release(r2.?.slot_idx);
}

test "Reassembler: out-of-order fragments" {
    var ra = Reassembler{};
    var buf1: [128]u8 = undefined;
    var buf2: [128]u8 = undefined;

    const payload1 = "AAAAAAAA"; // 8 bytes
    const payload2 = "BBBBBBBB"; // 8 bytes

    // Send fragment 2 first (offset=1, MF=0)
    const len2 = buildFragment(.{ 1, 2, 3, 4 }, .{ 5, 6, 7, 8 }, 200, 1, false, payload2, &buf2);
    const r2 = ra.inject(0, buf2[0..len2]);
    try testing.expect(r2 == null);

    // Then fragment 1 (offset=0, MF=1)
    const len1 = buildFragment(.{ 1, 2, 3, 4 }, .{ 5, 6, 7, 8 }, 200, 0, true, payload1, &buf1);
    const r1 = ra.inject(0, buf1[0..len1]);
    try testing.expect(r1 != null);
    try testing.expectEqualSlices(u8, "AAAAAAAABBBBBBBB", r1.?.data[0..16]);
    ra.release(r1.?.slot_idx);
}

test "Reassembler: timeout expires flow" {
    var ra = Reassembler{};
    var buf: [128]u8 = undefined;

    const payload = "XXXX";
    const len = buildFragment(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, 300, 0, true, payload, &buf);
    _ = ra.inject(0, buf[0..len]);

    // Verify slot is active
    try testing.expect(ra.slots[0].active);

    // Tick at 30001ms → should expire
    ra.tick(30_001);
    try testing.expect(!ra.slots[0].active);
}

test "Reassembler: non-fragmented returns null" {
    var ra = Reassembler{};
    var buf: [128]u8 = undefined;

    // Non-fragmented (offset=0, MF=0)
    const payload = "hello";
    const ip_hlen: usize = 20;
    const total: usize = ip_hlen + payload.len;
    var ip = ipv4_header.MutableHeader.init(buf[0..ip_hlen]) catch unreachable;
    ip.setTotalLen(@intCast(total));
    ip.setTtl(64);
    ip.setProtocol(.tcp);
    ip.setSrcAddr(.{ 10, 0, 0, 1 });
    ip.setDstAddr(.{ 10, 0, 0, 2 });
    ip.setDontFragment();
    ip.computeChecksum();
    @memcpy(buf[ip_hlen .. ip_hlen + payload.len], payload);

    const result = ra.inject(0, buf[0..total]);
    try testing.expect(result == null);
}
