// SYN Cookies (RFC 4987): Stateless SYN flood defense.
//
// When the listen backlog is near full, instead of allocating connection state
// for each SYN, we encode essential info into the ISN of the SYN+ACK:
//
//   ISN = hash(secret, 4-tuple, t) | (mss_idx << 3) | (t & 0x7)
//
// Where:
//   - t = timestamp counter (wraps every ~64 seconds)
//   - mss_idx = 3-bit MSS class encoding
//   - hash covers the 4-tuple + secret + t for validation
//
// On receiving the final ACK, we validate the cookie by recomputing the hash.
// If valid, we reconstruct connection state without ever having stored it.
//
// Sans-IO: no timers or I/O, purely deterministic given (now_ms, 4-tuple, secret).

const std = @import("std");

pub const SynCookie = struct {
    secret: [16]u8,

    pub fn init(secret: [16]u8) SynCookie {
        return .{ .secret = secret };
    }

    /// Generate a SYN cookie ISN for a SYN+ACK response.
    pub fn generate(self: *const SynCookie, now_ms: u64, src_addr: [4]u8, src_port: u16, dst_addr: [4]u8, dst_port: u16, peer_mss: u16) u32 {
        const t: u5 = @truncate(now_ms / 64_000);
        const mss_idx = encodeMss(peer_mss);
        const hash = self.cookieHash(src_addr, src_port, dst_addr, dst_port, t);
        // Low 3 bits: t, next 3 bits: mss_idx, rest: hash
        return (hash & 0xFFFFFFC0) | (@as(u32, mss_idx) << 3) | @as(u32, t & 0x7);
    }

    /// Validate a cookie from the ACK's ack_num - 1 (since ACK acks ISN+1).
    /// Returns the decoded MSS if valid, null if invalid.
    pub fn validate(self: *const SynCookie, now_ms: u64, src_addr: [4]u8, src_port: u16, dst_addr: [4]u8, dst_port: u16, cookie: u32) ?u16 {
        const t_recv: u5 = @truncate(cookie & 0x7);
        const mss_idx: u3 = @truncate((cookie >> 3) & 0x7);
        const t_now: u5 = @truncate(now_ms / 64_000);

        // Accept if t matches now or one period ago
        const valid_time = (t_recv == (t_now & 0x7)) or (t_recv == ((t_now -% 1) & 0x7));
        if (!valid_time) return null;

        // Try current period
        const hash_now = self.cookieHash(src_addr, src_port, dst_addr, dst_port, @truncate(t_now & 0x1F));
        const expected_now = (hash_now & 0xFFFFFFC0) | (@as(u32, mss_idx) << 3) | @as(u32, t_recv);
        if (cookie == expected_now) return decodeMss(mss_idx);

        // Try previous period
        const t_prev: u5 = @truncate((t_now -% 1) & 0x1F);
        const hash_prev = self.cookieHash(src_addr, src_port, dst_addr, dst_port, t_prev);
        const expected_prev = (hash_prev & 0xFFFFFFC0) | (@as(u32, mss_idx) << 3) | @as(u32, t_recv);
        if (cookie == expected_prev) return decodeMss(mss_idx);

        return null;
    }

    fn cookieHash(self: *const SynCookie, src_addr: [4]u8, src_port: u16, dst_addr: [4]u8, dst_port: u16, t: u5) u32 {
        var h: u32 = 2166136261;
        for (src_addr) |b| h = fnv(h, b);
        for (dst_addr) |b| h = fnv(h, b);
        h = fnv(h, @intCast(src_port >> 8));
        h = fnv(h, @intCast(src_port & 0xFF));
        h = fnv(h, @intCast(dst_port >> 8));
        h = fnv(h, @intCast(dst_port & 0xFF));
        h = fnv(h, @as(u8, t));
        for (self.secret) |b| h = fnv(h, b);
        return h;
    }

    fn fnv(h: u32, byte: u8) u32 {
        return (h ^ @as(u32, byte)) *% 16777619;
    }

    /// Encode MSS into 3-bit index (8 classes).
    fn encodeMss(mss: u16) u3 {
        if (mss >= 1460) return 7;
        if (mss >= 1440) return 6;
        if (mss >= 1300) return 5;
        if (mss >= 1200) return 4;
        if (mss >= 1024) return 3;
        if (mss >= 536) return 2;
        if (mss >= 512) return 1;
        return 0;
    }

    /// Decode 3-bit MSS index back to representative MSS.
    fn decodeMss(idx: u3) u16 {
        return switch (idx) {
            0 => 216,
            1 => 512,
            2 => 536,
            3 => 1024,
            4 => 1200,
            5 => 1300,
            6 => 1440,
            7 => 1460,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "SynCookie: generate and validate roundtrip" {
    const sc = SynCookie.init(.{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 });

    const cookie = sc.generate(1000, .{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1460);
    const mss = sc.validate(1000, .{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, cookie);
    try testing.expect(mss != null);
    try testing.expectEqual(@as(u16, 1460), mss.?);
}

test "SynCookie: validate within one period" {
    const sc = SynCookie.init(.{0xAA} ** 16);

    // Generate at t=0
    const cookie = sc.generate(0, .{ 192, 168, 1, 2 }, 8080, .{ 192, 168, 1, 1 }, 443, 1300);
    // Validate at same time
    const mss1 = sc.validate(0, .{ 192, 168, 1, 2 }, 8080, .{ 192, 168, 1, 1 }, 443, cookie);
    try testing.expect(mss1 != null);
    try testing.expectEqual(@as(u16, 1300), mss1.?);

    // Validate one period later (64s)
    const mss2 = sc.validate(64_000, .{ 192, 168, 1, 2 }, 8080, .{ 192, 168, 1, 1 }, 443, cookie);
    try testing.expect(mss2 != null);
}

test "SynCookie: reject after two periods" {
    const sc = SynCookie.init(.{0xBB} ** 16);

    const cookie = sc.generate(0, .{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1460);
    // Two periods later → should fail
    const mss = sc.validate(128_001, .{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, cookie);
    try testing.expect(mss == null);
}

test "SynCookie: wrong 4-tuple rejected" {
    const sc = SynCookie.init(.{0xCC} ** 16);

    const cookie = sc.generate(1000, .{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1460);
    // Different source port → invalid
    const mss = sc.validate(1000, .{ 10, 0, 0, 2 }, 5001, .{ 10, 0, 0, 1 }, 80, cookie);
    try testing.expect(mss == null);
}

test "SynCookie: MSS encoding covers all classes" {
    const sc = SynCookie.init(.{0xDD} ** 16);

    const test_cases = [_]struct { mss: u16, expected: u16 }{
        .{ .mss = 200, .expected = 216 },
        .{ .mss = 512, .expected = 512 },
        .{ .mss = 536, .expected = 536 },
        .{ .mss = 1024, .expected = 1024 },
        .{ .mss = 1200, .expected = 1200 },
        .{ .mss = 1300, .expected = 1300 },
        .{ .mss = 1440, .expected = 1440 },
        .{ .mss = 1460, .expected = 1460 },
    };

    for (test_cases) |tc| {
        const cookie = sc.generate(0, .{ 1, 2, 3, 4 }, 100, .{ 5, 6, 7, 8 }, 200, tc.mss);
        const result = sc.validate(0, .{ 1, 2, 3, 4 }, 100, .{ 5, 6, 7, 8 }, 200, cookie);
        try testing.expect(result != null);
        try testing.expectEqual(tc.expected, result.?);
    }
}
