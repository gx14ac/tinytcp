// UDP header parser/serializer (RFC 768).
// Simple 8-byte fixed header.

const std = @import("std");
const checksum = @import("../checksum.zig");

/// UDP header size (always 8 bytes).
pub const header_len: usize = 8;

/// Parsed UDP header (view over raw bytes).
pub const Header = struct {
    bytes: []const u8,

    pub fn parse(data: []const u8) error{TooShort}!Header {
        if (data.len < header_len) return error.TooShort;
        return Header{ .bytes = data[0..header_len] };
    }

    /// Source port.
    pub fn srcPort(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[0..2], .big);
    }

    /// Destination port.
    pub fn dstPort(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[2..4], .big);
    }

    /// Total datagram length (header + payload).
    pub fn length(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[4..6], .big);
    }

    /// Payload length (total - header).
    pub fn payloadLen(self: Header) u16 {
        return self.length() -| @as(u16, header_len);
    }

    /// Checksum field (0 means no checksum in IPv4).
    pub fn checksumField(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[6..8], .big);
    }

    /// Get the payload slice.
    pub fn payload(self: Header, full_datagram: []const u8) []const u8 {
        const total = @as(usize, self.length());
        if (full_datagram.len < total) {
            return full_datagram[header_len..];
        }
        return full_datagram[header_len..total];
    }

    /// Verify checksum with IPv4 pseudo-header.
    /// A checksum of 0 in IPv4 means "no checksum" and is considered valid.
    pub fn verifyChecksumIpv4(self: Header, src: [4]u8, dst: [4]u8, full_datagram: []const u8) bool {
        if (self.checksumField() == 0) return true; // no checksum
        const ph = checksum.pseudoHeaderIpv4(src, dst, 17, @intCast(full_datagram.len));
        const sum = checksum.accumulate(ph, full_datagram);
        return checksum.finish(sum) == 0;
    }

    /// Verify checksum with IPv6 pseudo-header (RFC 8200 §8.1: mandatory, checksum=0 means drop).
    pub fn verifyChecksumIpv6(self: Header, src: [16]u8, dst: [16]u8, full_datagram: []const u8) bool {
        if (self.checksumField() == 0) return false; // mandatory in IPv6
        const ph = checksum.pseudoHeaderIpv6(src, dst, 17, @intCast(full_datagram.len));
        const sum = checksum.accumulate(ph, full_datagram);
        return checksum.finish(sum) == 0;
    }
};

/// Mutable UDP header for building packets.
pub const MutableHeader = struct {
    bytes: []u8,

    pub fn init(buf: []u8) error{TooShort}!MutableHeader {
        if (buf.len < header_len) return error.TooShort;
        @memset(buf[0..header_len], 0);
        return MutableHeader{ .bytes = buf[0..header_len] };
    }

    pub fn setSrcPort(self: *MutableHeader, port: u16) void {
        std.mem.writeInt(u16, self.bytes[0..2], port, .big);
    }

    pub fn setDstPort(self: *MutableHeader, port: u16) void {
        std.mem.writeInt(u16, self.bytes[2..4], port, .big);
    }

    pub fn setLength(self: *MutableHeader, len: u16) void {
        std.mem.writeInt(u16, self.bytes[4..6], len, .big);
    }

    /// Compute and write checksum using IPv4 pseudo-header.
    pub fn computeChecksumIpv4(self: *MutableHeader, src: [4]u8, dst: [4]u8, full_datagram: []u8) void {
        // Clear checksum field
        full_datagram[6] = 0;
        full_datagram[7] = 0;
        const ph = checksum.pseudoHeaderIpv4(src, dst, 17, @intCast(full_datagram.len));
        const sum = checksum.accumulate(ph, full_datagram);
        const cksum = checksum.finish(sum);
        // If checksum is 0, set to 0xFFFF (RFC 768)
        const final = if (cksum == 0) @as(u16, 0xFFFF) else cksum;
        std.mem.writeInt(u16, self.bytes[6..8], final, .big);
    }

    pub fn asConst(self: MutableHeader) Header {
        return Header{ .bytes = self.bytes };
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "udp: parse header" {
    const pkt = [_]u8{
        0x00, 0x35, 0xC0, 0x00, // src=53, dst=49152
        0x00, 0x1C, 0x00, 0x00, // length=28, checksum=0
        // payload would follow...
    };

    const hdr = try Header.parse(&pkt);
    try testing.expectEqual(@as(u16, 53), hdr.srcPort());
    try testing.expectEqual(@as(u16, 49152), hdr.dstPort());
    try testing.expectEqual(@as(u16, 28), hdr.length());
    try testing.expectEqual(@as(u16, 20), hdr.payloadLen());
}

test "udp: reject too short" {
    const short = [_]u8{ 0x00, 0x35, 0xC0 };
    try testing.expectError(error.TooShort, Header.parse(&short));
}

test "udp: mutable build" {
    var buf: [8]u8 = undefined;
    var hdr = try MutableHeader.init(&buf);
    hdr.setSrcPort(1234);
    hdr.setDstPort(5678);
    hdr.setLength(20);

    const view = hdr.asConst();
    try testing.expectEqual(@as(u16, 1234), view.srcPort());
    try testing.expectEqual(@as(u16, 5678), view.dstPort());
    try testing.expectEqual(@as(u16, 20), view.length());
}

test "udp: zero checksum is valid in ipv4" {
    const pkt = [_]u8{
        0x00, 0x35, 0xC0, 0x00,
        0x00, 0x08, 0x00, 0x00, // checksum=0
    };
    const hdr = try Header.parse(&pkt);
    try testing.expect(hdr.verifyChecksumIpv4(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, &pkt));
}

test "udp: zero checksum is invalid in ipv6" {
    const pkt = [_]u8{
        0x00, 0x35, 0xC0, 0x00,
        0x00, 0x08, 0x00, 0x00, // checksum=0
    };
    const hdr = try Header.parse(&pkt);
    const src6 = [_]u8{0} ** 16;
    const dst6 = [_]u8{0} ** 16;
    try testing.expect(!hdr.verifyChecksumIpv6(src6, dst6, &pkt));
}
