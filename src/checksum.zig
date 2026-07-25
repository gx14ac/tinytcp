// Internet checksum (RFC 1071) implementation.
// Supports one-shot computation and incremental updates.

const std = @import("std");
const mem = std.mem;

/// Compute the internet checksum over a byte slice.
/// Returns the 16-bit ones-complement checksum.
pub fn compute(data: []const u8) u16 {
    return finish(accumulate(0, data));
}

/// Accumulate partial checksum state. Can be called multiple times
/// to compute checksum over non-contiguous data.
/// noinline: works around Zig codegen bug on thumb-freestanding-eabi + ReleaseSmall
/// where inlining causes incorrect register scheduling for the accumulation loop.
pub noinline fn accumulate(initial: u32, data: []const u8) u32 {
    var sum: u32 = initial;
    var i: usize = 0;

    // Process 16-bit words — use readInt for portability across endianness/alignment
    while (i + 1 < data.len) : (i += 2) {
        sum += mem.readInt(u16, data[i..][0..2], .big);
    }

    // Handle odd byte
    if (i < data.len) {
        sum += @as(u32, data[i]) << 8;
    }

    return sum;
}

/// Finalize accumulated checksum into the 16-bit result.
pub noinline fn finish(sum: u32) u16 {
    var s = sum;
    // Fold 32-bit sum into 16 bits
    while (s >> 16 != 0) {
        s = (s & 0xFFFF) + (s >> 16);
    }
    return ~@as(u16, @intCast(s));
}

/// Verify that a checksum over data (including the checksum field) is valid.
/// A valid checksum yields 0x0000 when computed over the entire header.
pub fn verify(data: []const u8) bool {
    return compute(data) == 0;
}

/// Incremental checksum update (RFC 1624).
/// Given old checksum, old 16-bit value, and new 16-bit value,
/// compute the updated checksum without re-scanning the entire packet.
pub fn incrementalUpdate(old_checksum: u16, old_value: u16, new_value: u16) u16 {
    // HC' = ~(~HC + ~m + m')  where HC = checksum, m = old, m' = new
    const hc: u32 = ~@as(u32, old_checksum) & 0xFFFF;
    const m: u32 = ~@as(u32, old_value) & 0xFFFF;
    const mp: u32 = @as(u32, new_value);
    var sum: u32 = hc + m + mp;
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~@as(u16, @intCast(sum));
}

/// Compute pseudo-header checksum for TCP/UDP over IPv4.
/// This is accumulated with the transport header+payload checksum.
pub fn pseudoHeaderIpv4(src: [4]u8, dst: [4]u8, protocol: u8, length: u16) u32 {
    var sum: u32 = 0;
    sum += @as(u32, src[0]) << 8 | @as(u32, src[1]);
    sum += @as(u32, src[2]) << 8 | @as(u32, src[3]);
    sum += @as(u32, dst[0]) << 8 | @as(u32, dst[1]);
    sum += @as(u32, dst[2]) << 8 | @as(u32, dst[3]);
    sum += @as(u32, protocol);
    sum += @as(u32, length);
    return sum;
}

/// Compute pseudo-header checksum for TCP/UDP over IPv6.
pub fn pseudoHeaderIpv6(src: [16]u8, dst: [16]u8, next_header: u8, length: u32) u32 {
    var sum: u32 = 0;
    // Source address (8 x 16-bit words)
    var i: usize = 0;
    while (i < 16) : (i += 2) {
        sum += @as(u32, src[i]) << 8 | @as(u32, src[i + 1]);
    }
    // Destination address
    i = 0;
    while (i < 16) : (i += 2) {
        sum += @as(u32, dst[i]) << 8 | @as(u32, dst[i + 1]);
    }
    // Upper-layer packet length (32-bit)
    sum += @as(u32, @intCast(length >> 16));
    sum += @as(u32, @intCast(length & 0xFFFF));
    // Next header (zero-padded to 32 bits, only last 8 bits matter)
    sum += @as(u32, next_header);
    return sum;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "checksum: simple" {
    // Example from RFC 1071
    const data = [_]u8{ 0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7 };
    const cksum = compute(&data);
    // Verify: sum of data + checksum should yield 0
    var sum: u32 = accumulate(0, &data);
    sum += cksum;
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    try testing.expectEqual(@as(u16, 0xFFFF), @as(u16, @intCast(sum)));
}

test "checksum: all zeros" {
    const data = [_]u8{0} ** 20;
    try testing.expectEqual(@as(u16, 0xFFFF), compute(&data));
}

test "checksum: incremental update" {
    const data = [_]u8{ 0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7 };
    const original = compute(&data);

    // Change TTL from 0x40 to 0x39
    const old_word: u16 = 0x4011; // TTL=0x40, protocol=0x11
    const new_word: u16 = 0x3911; // TTL=0x39, protocol=0x11
    const updated = incrementalUpdate(original, old_word, new_word);

    // Verify by recomputing
    var modified = data;
    modified[8] = 0x39; // new TTL
    // Clear checksum field
    modified[10] = 0;
    modified[11] = 0;
    const recomputed = compute(&modified);
    try testing.expectEqual(recomputed, updated);
}

test "checksum: pseudo header ipv4" {
    const src = [4]u8{ 192, 168, 1, 1 };
    const dst = [4]u8{ 192, 168, 1, 2 };
    const ph = pseudoHeaderIpv4(src, dst, 6, 20); // TCP, 20 bytes
    // Just verify it doesn't crash and produces non-zero
    try testing.expect(ph != 0);
}

test "checksum: verify valid" {
    // Construct a packet with valid checksum
    var data = [_]u8{ 0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7 };
    const cksum = compute(&data);
    data[10] = @intCast(cksum >> 8);
    data[11] = @intCast(cksum & 0xFF);
    try testing.expect(verify(&data));
}
