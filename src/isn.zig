// Secure Initial Sequence Number generation (RFC 6528).
//
// ISN = hash(src_addr, dst_addr, src_port, dst_port, secret) + clock_based_offset
//
// Uses a simple 32-bit hash (FNV-1a based) since we don't have SipHash in Zig stdlib.
// The secret key prevents off-path attackers from predicting ISNs.
// Clock component ensures monotonicity across connections to the same 4-tuple.

const std = @import("std");

pub const IsnGenerator = struct {
    secret: [16]u8,
    clock_offset: u32 = 0,

    pub fn init(secret: [16]u8) IsnGenerator {
        return .{ .secret = secret };
    }

    pub fn generate(self: *IsnGenerator, now_ms: u64, local_addr: [4]u8, local_port: u16, remote_addr: [4]u8, remote_port: u16) u32 {
        // Hash the 4-tuple + secret using FNV-1a
        var h: u32 = 2166136261; // FNV offset basis

        // Mix in addresses and ports
        for (local_addr) |b| h = fnvMix(h, b);
        for (remote_addr) |b| h = fnvMix(h, b);
        h = fnvMix(h, @intCast(local_port >> 8));
        h = fnvMix(h, @intCast(local_port & 0xFF));
        h = fnvMix(h, @intCast(remote_port >> 8));
        h = fnvMix(h, @intCast(remote_port & 0xFF));

        // Mix in secret
        for (self.secret) |b| h = fnvMix(h, b);

        // Clock component: RFC 6528 says ISN increments ~250kHz (4μs per tick)
        // We use ms, so approximate: now_ms * 250 (ticks per ms)
        const clock_component: u32 = @truncate(now_ms *% 250);

        return h +% clock_component +% self.clock_offset;
    }

    fn fnvMix(h: u32, byte: u8) u32 {
        return (h ^ @as(u32, byte)) *% 16777619; // FNV prime
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "IsnGenerator: different 4-tuples produce different ISNs" {
    var gen = IsnGenerator.init(.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 });

    const isn1 = gen.generate(1000, .{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 80);
    const isn2 = gen.generate(1000, .{ 10, 0, 0, 1 }, 5001, .{ 10, 0, 0, 2 }, 80);
    const isn3 = gen.generate(1000, .{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 3 }, 80);

    try testing.expect(isn1 != isn2);
    try testing.expect(isn1 != isn3);
    try testing.expect(isn2 != isn3);
}

test "IsnGenerator: same 4-tuple at different times produces different ISNs" {
    var gen = IsnGenerator.init(.{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00 });

    const isn1 = gen.generate(0, .{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 80);
    const isn2 = gen.generate(100, .{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 80);
    const isn3 = gen.generate(200, .{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 80);

    try testing.expect(isn1 != isn2);
    try testing.expect(isn2 != isn3);
}

test "IsnGenerator: clock monotonicity" {
    var gen = IsnGenerator.init(.{0} ** 16);

    var prev = gen.generate(0, .{ 1, 2, 3, 4 }, 80, .{ 5, 6, 7, 8 }, 443);
    var monotonic = true;
    var i: u64 = 1;
    while (i <= 100) : (i += 1) {
        const curr = gen.generate(i * 4, .{ 1, 2, 3, 4 }, 80, .{ 5, 6, 7, 8 }, 443);
        if (@as(i32, @bitCast(curr -% prev)) <= 0) {
            monotonic = false;
            break;
        }
        prev = curr;
    }
    try testing.expect(monotonic);
}
