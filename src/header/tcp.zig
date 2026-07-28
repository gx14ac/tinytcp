// TCP header parser/serializer (RFC 9293).
// Supports parsing of common options: MSS, Window Scale, SACK Permitted, SACK, Timestamps.

const std = @import("std");
const checksum = @import("../checksum.zig");

/// Minimum TCP header size (no options).
pub const min_header_len: usize = 20;

/// Maximum TCP header size.
pub const max_header_len: usize = 60;

/// TCP flags.
pub const Flags = packed struct(u8) {
    fin: bool = false,
    syn: bool = false,
    rst: bool = false,
    psh: bool = false,
    ack: bool = false,
    urg: bool = false,
    ece: bool = false,
    cwr: bool = false,
};

/// TCP option kinds.
pub const OptionKind = enum(u8) {
    end = 0,
    nop = 1,
    mss = 2,
    window_scale = 3,
    sack_permitted = 4,
    sack = 5,
    timestamps = 8,
    _,
};

/// Parsed TCP option.
pub const Option = union(enum) {
    mss: u16,
    window_scale: u8,
    sack_permitted: void,
    sack: []const [2]u32, // pairs of (left_edge, right_edge)
    timestamps: struct { ts_val: u32, ts_ecr: u32 },
    unknown: struct { kind: u8, data: []const u8 },
};

/// Parsed TCP header (view over raw bytes).
pub const Header = struct {
    bytes: []const u8,

    pub fn parse(data: []const u8) error{ TooShort, InvalidDataOffset }!Header {
        if (data.len < min_header_len) return error.TooShort;

        const data_offset = @as(usize, data[12] >> 4) * 4;
        if (data_offset < min_header_len) return error.InvalidDataOffset;
        if (data.len < data_offset) return error.TooShort;

        return Header{ .bytes = data[0..data_offset] };
    }

    /// Source port.
    pub fn srcPort(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[0..2], .big);
    }

    /// Destination port.
    pub fn dstPort(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[2..4], .big);
    }

    /// Sequence number.
    pub fn seqNum(self: Header) u32 {
        return std.mem.readInt(u32, self.bytes[4..8], .big);
    }

    /// Acknowledgment number.
    pub fn ackNum(self: Header) u32 {
        return std.mem.readInt(u32, self.bytes[8..12], .big);
    }

    /// Data offset (header length in bytes).
    pub fn headerLen(self: Header) usize {
        return @as(usize, self.bytes[12] >> 4) * 4;
    }

    /// TCP flags.
    pub fn flags(self: Header) Flags {
        return @bitCast(self.bytes[13]);
    }

    /// Window size (before scaling).
    pub fn windowSize(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[14..16], .big);
    }

    /// Checksum field.
    pub fn checksumField(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[16..18], .big);
    }

    /// Urgent pointer.
    pub fn urgentPointer(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[18..20], .big);
    }

    /// Options bytes (may be empty).
    pub fn optionsBytes(self: Header) []const u8 {
        if (self.headerLen() > min_header_len) {
            return self.bytes[min_header_len..self.headerLen()];
        }
        return &.{};
    }

    /// Iterator over parsed TCP options.
    pub fn iterOptions(self: Header) OptionIterator {
        return OptionIterator{ .data = self.optionsBytes(), .pos = 0 };
    }

    /// Verify checksum against pseudo-header (IPv4).
    pub fn verifyChecksumIpv4(_: Header, src: [4]u8, dst: [4]u8, full_segment: []const u8) bool {
        const ph = checksum.pseudoHeaderIpv4(src, dst, 6, @intCast(full_segment.len));
        const sum = checksum.accumulate(ph, full_segment);
        return checksum.finish(sum) == 0;
    }

    /// Verify checksum against pseudo-header (IPv6).
    pub fn verifyChecksumIpv6(_: Header, src: [16]u8, dst: [16]u8, full_segment: []const u8) bool {
        const ph = checksum.pseudoHeaderIpv6(src, dst, 6, @intCast(full_segment.len));
        const sum = checksum.accumulate(ph, full_segment);
        return checksum.finish(sum) == 0;
    }
};

/// TCP options iterator.
pub const OptionIterator = struct {
    data: []const u8,
    pos: usize,

    pub fn next(self: *OptionIterator) ?Option {
        while (self.pos < self.data.len) {
            const kind: OptionKind = @enumFromInt(self.data[self.pos]);
            switch (kind) {
                .end => return null,
                .nop => {
                    self.pos += 1;
                    continue;
                },
                else => {
                    if (self.pos + 1 >= self.data.len) return null;
                    const opt_len = self.data[self.pos + 1];
                    if (opt_len < 2 or self.pos + opt_len > self.data.len) return null;
                    defer self.pos += opt_len;

                    return switch (kind) {
                        .mss => blk: {
                            if (opt_len != 4) break :blk Option{ .unknown = .{ .kind = @intFromEnum(kind), .data = self.data[self.pos + 2 .. self.pos + opt_len] } };
                            break :blk Option{ .mss = std.mem.readInt(u16, self.data[self.pos + 2 .. self.pos + 4][0..2], .big) };
                        },
                        .window_scale => blk: {
                            if (opt_len != 3) break :blk Option{ .unknown = .{ .kind = @intFromEnum(kind), .data = self.data[self.pos + 2 .. self.pos + opt_len] } };
                            break :blk Option{ .window_scale = self.data[self.pos + 2] };
                        },
                        .sack_permitted => Option{ .sack_permitted = {} },
                        .timestamps => blk: {
                            if (opt_len != 10) break :blk Option{ .unknown = .{ .kind = @intFromEnum(kind), .data = self.data[self.pos + 2 .. self.pos + opt_len] } };
                            const ts_val = std.mem.readInt(u32, self.data[self.pos + 2 .. self.pos + 6][0..4], .big);
                            const ts_ecr = std.mem.readInt(u32, self.data[self.pos + 6 .. self.pos + 10][0..4], .big);
                            break :blk Option{ .timestamps = .{ .ts_val = ts_val, .ts_ecr = ts_ecr } };
                        },
                        else => Option{ .unknown = .{ .kind = @intFromEnum(kind), .data = self.data[self.pos + 2 .. self.pos + opt_len] } },
                    };
                },
            }
        }
        return null;
    }
};

/// Mutable TCP header for building packets.
pub const MutableHeader = struct {
    bytes: []u8,

    /// Initialize a minimal TCP header (20 bytes, data offset = 5).
    pub fn init(buf: []u8) error{TooShort}!MutableHeader {
        if (buf.len < min_header_len) return error.TooShort;
        @memset(buf[0..min_header_len], 0);
        buf[12] = 0x50; // data offset = 5 (20 bytes)
        return MutableHeader{ .bytes = buf[0..min_header_len] };
    }

    pub fn setSrcPort(self: *MutableHeader, port: u16) void {
        std.mem.writeInt(u16, self.bytes[0..2], port, .big);
    }

    pub fn setDstPort(self: *MutableHeader, port: u16) void {
        std.mem.writeInt(u16, self.bytes[2..4], port, .big);
    }

    pub fn setSeqNum(self: *MutableHeader, seq: u32) void {
        std.mem.writeInt(u32, self.bytes[4..8], seq, .big);
    }

    pub fn setAckNum(self: *MutableHeader, ack: u32) void {
        std.mem.writeInt(u32, self.bytes[8..12], ack, .big);
    }

    pub fn setFlags(self: *MutableHeader, f: Flags) void {
        self.bytes[13] = @bitCast(f);
    }

    pub fn setWindowSize(self: *MutableHeader, win: u16) void {
        std.mem.writeInt(u16, self.bytes[14..16], win, .big);
    }

    /// Compute and write checksum using IPv4 pseudo-header.
    pub fn computeChecksumIpv4(self: *MutableHeader, src: [4]u8, dst: [4]u8, full_segment: []u8) void {
        _ = self;
        // Clear checksum field
        full_segment[16] = 0;
        full_segment[17] = 0;
        const ph = checksum.pseudoHeaderIpv4(src, dst, 6, @intCast(full_segment.len));
        const sum = checksum.accumulate(ph, full_segment);
        const cksum = checksum.finish(sum);
        std.mem.writeInt(u16, full_segment[16..18], cksum, .big);
    }

    pub fn asConst(self: MutableHeader) Header {
        return Header{ .bytes = self.bytes };
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "tcp: parse minimal header" {
    var pkt = [_]u8{
        0x00, 0x50, 0x01, 0xBB, // src=80, dst=443
        0x00, 0x00, 0x00, 0x01, // seq=1
        0x00, 0x00, 0x00, 0x00, // ack=0
        0x50, 0x02, 0xFF, 0xFF, // offset=5, SYN, window=65535
        0x00, 0x00, 0x00, 0x00, // checksum=0, urgent=0
    };
    _ = &pkt;

    const hdr = try Header.parse(&pkt);
    try testing.expectEqual(@as(u16, 80), hdr.srcPort());
    try testing.expectEqual(@as(u16, 443), hdr.dstPort());
    try testing.expectEqual(@as(u32, 1), hdr.seqNum());
    try testing.expect(hdr.flags().syn);
    try testing.expect(!hdr.flags().ack);
    try testing.expectEqual(@as(u16, 65535), hdr.windowSize());
}

test "tcp: parse with MSS option" {
    const pkt = [_]u8{
        0x00, 0x50, 0x01, 0xBB, // src=80, dst=443
        0x00, 0x00, 0x00, 0x01, // seq=1
        0x00, 0x00, 0x00, 0x00, // ack=0
        0x60, 0x02, 0xFF, 0xFF, // offset=6 (24 bytes), SYN, window=65535
        0x00, 0x00, 0x00, 0x00, // checksum=0, urgent=0
        0x02, 0x04, 0x05, 0xB4, // MSS=1460
    };

    const hdr = try Header.parse(&pkt);
    try testing.expectEqual(@as(usize, 24), hdr.headerLen());

    var opts = hdr.iterOptions();
    const first = opts.next() orelse return error.TestUnexpectedResult;
    switch (first) {
        .mss => |mss| try testing.expectEqual(@as(u16, 1460), mss),
        else => return error.TestUnexpectedResult,
    }
}

test "tcp: parse with timestamps" {
    const pkt = [_]u8{
        0x00, 0x50, 0x01, 0xBB, // src=80, dst=443
        0x00, 0x00, 0x00, 0x01, // seq=1
        0x00, 0x00, 0x00, 0x01, // ack=1
        0x80, 0x10, 0xFF, 0xFF, // offset=8 (32 bytes), ACK, window=65535
        0x00, 0x00, 0x00, 0x00, // checksum=0, urgent=0
        0x01, // NOP
        0x01, // NOP
        0x08, 0x0A, // Timestamps, length=10
        0x00, 0x01, 0x00, 0x00, // ts_val=65536
        0x00, 0x00, 0x80, 0x00, // ts_ecr=32768
        0x00, 0x00, // padding
    };

    const hdr = try Header.parse(&pkt);
    var opts = hdr.iterOptions();
    const first = opts.next() orelse return error.TestUnexpectedResult;
    switch (first) {
        .timestamps => |ts| {
            try testing.expectEqual(@as(u32, 65536), ts.ts_val);
            try testing.expectEqual(@as(u32, 32768), ts.ts_ecr);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "tcp: flags" {
    const f = Flags{ .syn = true, .ack = true };
    try testing.expect(f.syn);
    try testing.expect(f.ack);
    try testing.expect(!f.fin);
    try testing.expect(!f.rst);
}
