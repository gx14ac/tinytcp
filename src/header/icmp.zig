// ICMPv4/v6 header parser (RFC 792, RFC 4443).
// Minimal parser for echo request/reply and error messages.

const std = @import("std");
const checksum = @import("../checksum.zig");

/// ICMP header size (type + code + checksum + rest-of-header).
pub const header_len: usize = 8;

/// ICMPv4 message types.
pub const Icmpv4Type = enum(u8) {
    echo_reply = 0,
    dest_unreachable = 3,
    redirect = 5,
    echo_request = 8,
    time_exceeded = 11,
    parameter_problem = 12,
    _,
};

/// ICMPv6 message types.
pub const Icmpv6Type = enum(u8) {
    dest_unreachable = 1,
    packet_too_big = 2,
    time_exceeded = 3,
    parameter_problem = 4,
    echo_request = 128,
    echo_reply = 129,
    _,
};

/// Parsed ICMP header (shared structure for v4 and v6).
pub const Header = struct {
    bytes: []const u8,

    pub fn parse(data: []const u8) error{TooShort}!Header {
        if (data.len < header_len) return error.TooShort;
        return Header{ .bytes = data[0..header_len] };
    }

    /// Message type (raw byte).
    pub fn msgType(self: Header) u8 {
        return self.bytes[0];
    }

    /// ICMPv4 type.
    pub fn icmpv4Type(self: Header) Icmpv4Type {
        return @enumFromInt(self.bytes[0]);
    }

    /// ICMPv6 type.
    pub fn icmpv6Type(self: Header) Icmpv6Type {
        return @enumFromInt(self.bytes[0]);
    }

    /// Code field.
    pub fn code(self: Header) u8 {
        return self.bytes[1];
    }

    /// Checksum field.
    pub fn checksumField(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[2..4], .big);
    }

    /// Rest-of-header (bytes 4-7). Interpretation depends on type.
    /// For echo: identifier (bytes 4-5) and sequence (bytes 6-7).
    pub fn identifier(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[4..6], .big);
    }

    pub fn sequence(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[6..8], .big);
    }

    /// For Packet Too Big (ICMPv6): MTU field.
    pub fn mtu(self: Header) u32 {
        return std.mem.readInt(u32, self.bytes[4..8], .big);
    }

    /// Verify ICMPv4 checksum (covers entire ICMP message).
    pub fn verifyChecksumIcmpv4(self: Header, full_message: []const u8) bool {
        _ = self;
        return checksum.verify(full_message);
    }

    /// Payload (everything after the 8-byte header).
    pub fn payload(self: Header, full_message: []const u8) []const u8 {
        _ = self;
        if (full_message.len <= header_len) return &.{};
        return full_message[header_len..];
    }
};

/// Mutable ICMP header for building messages.
pub const MutableHeader = struct {
    bytes: []u8,

    pub fn init(buf: []u8) error{TooShort}!MutableHeader {
        if (buf.len < header_len) return error.TooShort;
        @memset(buf[0..header_len], 0);
        return MutableHeader{ .bytes = buf[0..header_len] };
    }

    pub fn setType(self: *MutableHeader, msg_type: u8) void {
        self.bytes[0] = msg_type;
    }

    pub fn setCode(self: *MutableHeader, c: u8) void {
        self.bytes[1] = c;
    }

    pub fn setIdentifier(self: *MutableHeader, id: u16) void {
        std.mem.writeInt(u16, self.bytes[4..6], id, .big);
    }

    pub fn setSequence(self: *MutableHeader, seq: u16) void {
        std.mem.writeInt(u16, self.bytes[6..8], seq, .big);
    }

    /// Compute ICMPv4 checksum over the full message.
    pub fn computeChecksumIcmpv4(self: *MutableHeader, full_message: []u8) void {
        full_message[2] = 0;
        full_message[3] = 0;
        const cksum = checksum.compute(full_message);
        std.mem.writeInt(u16, self.bytes[2..4], cksum, .big);
    }

    pub fn asConst(self: MutableHeader) Header {
        return Header{ .bytes = self.bytes };
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "icmp: parse echo request" {
    var pkt = [_]u8{
        0x08, 0x00, 0x00, 0x00, // type=8 (echo request), code=0, checksum=0
        0x00, 0x01, 0x00, 0x01, // id=1, seq=1
    };
    // Compute checksum
    const cksum = checksum.compute(&pkt);
    pkt[2] = @intCast(cksum >> 8);
    pkt[3] = @intCast(cksum & 0xFF);

    const hdr = try Header.parse(&pkt);
    try testing.expectEqual(Icmpv4Type.echo_request, hdr.icmpv4Type());
    try testing.expectEqual(@as(u8, 0), hdr.code());
    try testing.expectEqual(@as(u16, 1), hdr.identifier());
    try testing.expectEqual(@as(u16, 1), hdr.sequence());
    try testing.expect(hdr.verifyChecksumIcmpv4(&pkt));
}

test "icmp: reject too short" {
    const short = [_]u8{ 0x08, 0x00, 0x00 };
    try testing.expectError(error.TooShort, Header.parse(&short));
}

test "icmp: mutable build echo reply" {
    var buf: [8]u8 = undefined;
    var hdr = try MutableHeader.init(&buf);
    hdr.setType(@intFromEnum(Icmpv4Type.echo_reply));
    hdr.setCode(0);
    hdr.setIdentifier(42);
    hdr.setSequence(7);
    hdr.computeChecksumIcmpv4(&buf);

    const view = hdr.asConst();
    try testing.expectEqual(Icmpv4Type.echo_reply, view.icmpv4Type());
    try testing.expectEqual(@as(u16, 42), view.identifier());
    try testing.expectEqual(@as(u16, 7), view.sequence());
    try testing.expect(view.verifyChecksumIcmpv4(&buf));
}
