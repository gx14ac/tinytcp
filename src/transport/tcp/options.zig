// TCP Options negotiation and serialization.
//
// Handles TCP options during handshake:
// - MSS (RFC 9293)
// - Window Scale (RFC 7323)
// - Timestamps (RFC 7323)
// - SACK Permitted (RFC 2018)
//
// Sans-IO: this module only parses/builds option bytes.

const std = @import("std");

/// TCP Option kinds.
pub const Kind = enum(u8) {
    end = 0,
    nop = 1,
    mss = 2,
    window_scale = 3,
    sack_permitted = 4,
    sack = 5,
    timestamps = 8,
    _,
};

/// Negotiated TCP options for a connection.
pub const NegotiatedOptions = struct {
    /// Maximum Segment Size.
    mss: u16 = 1460,
    /// Window scale factor (shift count, 0-14).
    window_scale: u8 = 0,
    /// Whether the peer included the Window Scale option in its SYN.
    window_scale_offered: bool = false,
    /// Whether SACK is permitted.
    sack_permitted: bool = false,
    /// Whether timestamps are enabled.
    timestamps_enabled: bool = false,
};

/// Options to offer during SYN.
pub const SynOptions = struct {
    mss: u16 = 1460,
    window_scale: ?u8 = 7, // default: 7 → 128x = 8MB window
    sack_permitted: bool = true,
    timestamps: bool = true,
};

/// Serialize SYN options into a byte buffer.
/// Returns the number of bytes written.
pub fn writeSynOptions(buf: []u8, opts: SynOptions) usize {
    var pos: usize = 0;

    // MSS (4 bytes: kind=2, len=4, value)
    if (pos + 4 <= buf.len) {
        buf[pos] = @intFromEnum(Kind.mss);
        buf[pos + 1] = 4;
        buf[pos + 2] = @intCast(opts.mss >> 8);
        buf[pos + 3] = @intCast(opts.mss & 0xFF);
        pos += 4;
    }

    // Window Scale (3 bytes + 1 NOP for alignment: NOP, kind=3, len=3, shift)
    if (opts.window_scale) |ws| {
        if (pos + 4 <= buf.len) {
            buf[pos] = @intFromEnum(Kind.nop);
            buf[pos + 1] = @intFromEnum(Kind.window_scale);
            buf[pos + 2] = 3;
            buf[pos + 3] = ws;
            pos += 4;
        }
    }

    // SACK Permitted (2 bytes + 2 NOP: NOP, NOP, kind=4, len=2)
    if (opts.sack_permitted) {
        if (pos + 4 <= buf.len) {
            buf[pos] = @intFromEnum(Kind.nop);
            buf[pos + 1] = @intFromEnum(Kind.nop);
            buf[pos + 2] = @intFromEnum(Kind.sack_permitted);
            buf[pos + 3] = 2;
            pos += 4;
        }
    }

    // Timestamps (10 bytes + 2 NOP: NOP, NOP, kind=8, len=10, TSval[4], TSecr[4])
    if (opts.timestamps) {
        if (pos + 12 <= buf.len) {
            buf[pos] = @intFromEnum(Kind.nop);
            buf[pos + 1] = @intFromEnum(Kind.nop);
            buf[pos + 2] = @intFromEnum(Kind.timestamps);
            buf[pos + 3] = 10;
            // TSval and TSecr will be filled by caller
            @memset(buf[pos + 4 .. pos + 12], 0);
            pos += 12;
        }
    }

    return pos;
}

/// Parse options from a raw options byte slice.
/// Returns negotiated options.
pub fn parseOptions(data: []const u8) NegotiatedOptions {
    var result = NegotiatedOptions{};
    var i: usize = 0;

    while (i < data.len) {
        const kind: Kind = @enumFromInt(data[i]);
        switch (kind) {
            .end => break,
            .nop => {
                i += 1;
                continue;
            },
            .mss => {
                if (i + 4 <= data.len and data[i + 1] == 4) {
                    result.mss = @as(u16, data[i + 2]) << 8 | @as(u16, data[i + 3]);
                    i += 4;
                } else break;
            },
            .window_scale => {
                if (i + 3 <= data.len and data[i + 1] == 3) {
                    result.window_scale = @min(data[i + 2], 14); // RFC: max 14
                    result.window_scale_offered = true;
                    i += 3;
                } else break;
            },
            .sack_permitted => {
                if (i + 2 <= data.len and data[i + 1] == 2) {
                    result.sack_permitted = true;
                    i += 2;
                } else break;
            },
            .sack => {
                // SACK blocks — skip using length
                if (i + 1 < data.len) {
                    const len = data[i + 1];
                    if (len < 2) break;
                    i += @as(usize, len);
                } else break;
            },
            .timestamps => {
                if (i + 10 <= data.len and data[i + 1] == 10) {
                    result.timestamps_enabled = true;
                    i += 10;
                } else break;
            },
            _ => {
                // Unknown option: skip using length byte
                if (i + 1 < data.len) {
                    const len = data[i + 1];
                    if (len < 2) break; // invalid
                    i += @as(usize, len);
                } else break;
            },
        }
    }

    return result;
}

/// Write timestamp option into existing buffer at given offset.
/// Used for data segments (not SYN).
pub fn writeTimestamp(buf: []u8, tsval: u32, tsecr: u32) usize {
    if (buf.len < 12) return 0;
    buf[0] = @intFromEnum(Kind.nop);
    buf[1] = @intFromEnum(Kind.nop);
    buf[2] = @intFromEnum(Kind.timestamps);
    buf[3] = 10;
    std.mem.writeInt(u32, buf[4..8], tsval, .big);
    std.mem.writeInt(u32, buf[8..12], tsecr, .big);
    return 12;
}

/// SACK block (left edge, right edge) — received from peer.
pub const SackBlock = struct {
    left: u32,
    right: u32,
};

/// Parse SACK blocks from TCP options data.
/// Returns the number of SACK blocks found (max 4).
pub fn parseSackBlocks(data: []const u8, out: *[4]SackBlock) u8 {
    var i: usize = 0;
    while (i < data.len) {
        const kind: Kind = @enumFromInt(data[i]);
        switch (kind) {
            .end => break,
            .nop => {
                i += 1;
            },
            .sack => {
                if (i + 1 >= data.len) break;
                const opt_len = data[i + 1];
                if (opt_len < 2 or i + opt_len > data.len) break;
                // Each SACK block is 8 bytes (left[4] + right[4])
                const block_bytes = opt_len - 2;
                const num_blocks = block_bytes / 8;
                var count: u8 = 0;
                var j: usize = i + 2;
                while (count < num_blocks and count < 4) : (count += 1) {
                    out[count] = .{
                        .left = std.mem.readInt(u32, data[j..][0..4], .big),
                        .right = std.mem.readInt(u32, data[j + 4 ..][0..4], .big),
                    };
                    j += 8;
                }
                return count;
            },
            else => {
                if (i + 1 < data.len) {
                    const len = data[i + 1];
                    if (len < 2) break;
                    i += @as(usize, len);
                } else break;
            },
        }
    }
    return 0;
}

/// Read timestamp values from options data.
pub fn readTimestamp(data: []const u8) ?struct { tsval: u32, tsecr: u32 } {
    var i: usize = 0;
    while (i < data.len) {
        const kind: Kind = @enumFromInt(data[i]);
        switch (kind) {
            .end => break,
            .nop => {
                i += 1;
            },
            .timestamps => {
                if (i + 10 <= data.len and data[i + 1] == 10) {
                    const tsval = std.mem.readInt(u32, data[i + 2 ..][0..4], .big);
                    const tsecr = std.mem.readInt(u32, data[i + 6 ..][0..4], .big);
                    return .{ .tsval = tsval, .tsecr = tsecr };
                }
                break;
            },
            .mss, .window_scale, .sack_permitted, .sack => {
                // Skip using length byte
                if (i + 1 < data.len) {
                    const len = data[i + 1];
                    if (len < 2) break;
                    i += @as(usize, len);
                } else break;
            },
            _ => {
                if (i + 1 < data.len) {
                    const len = data[i + 1];
                    if (len < 2) break;
                    i += @as(usize, len);
                } else break;
            },
        }
    }
    return null;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "options: write and parse SYN options" {
    var buf: [40]u8 = undefined;
    const len = writeSynOptions(&buf, .{
        .mss = 1460,
        .window_scale = 7,
        .sack_permitted = true,
        .timestamps = true,
    });
    try testing.expect(len > 0);
    try testing.expect(len <= 40);

    const parsed = parseOptions(buf[0..len]);
    try testing.expectEqual(@as(u16, 1460), parsed.mss);
    try testing.expectEqual(@as(u8, 7), parsed.window_scale);
    try testing.expect(parsed.window_scale_offered);
    try testing.expect(parsed.sack_permitted);
    try testing.expect(parsed.timestamps_enabled);
}

test "options: parse MSS only" {
    const data = [_]u8{ 2, 4, 0x05, 0xB4, 0 }; // MSS=1460, END
    const parsed = parseOptions(&data);
    try testing.expectEqual(@as(u16, 1460), parsed.mss);
    try testing.expectEqual(@as(u8, 0), parsed.window_scale);
    try testing.expect(!parsed.window_scale_offered);
}

test "options: window scale clamped to 14" {
    const data = [_]u8{ 3, 3, 20, 0 }; // WS=20 → clamped to 14
    const parsed = parseOptions(&data);
    try testing.expectEqual(@as(u8, 14), parsed.window_scale);
    try testing.expect(parsed.window_scale_offered);
}

test "options: window scale 0 is distinct from absent" {
    const data = [_]u8{ 3, 3, 0, 0 }; // WS=0, END
    const parsed = parseOptions(&data);
    try testing.expectEqual(@as(u8, 0), parsed.window_scale);
    try testing.expect(parsed.window_scale_offered);
}

test "options: timestamp write and read" {
    var buf: [12]u8 = undefined;
    const len = writeTimestamp(&buf, 12345, 67890);
    try testing.expectEqual(@as(usize, 12), len);

    const ts = readTimestamp(&buf);
    try testing.expect(ts != null);
    try testing.expectEqual(@as(u32, 12345), ts.?.tsval);
    try testing.expectEqual(@as(u32, 67890), ts.?.tsecr);
}
