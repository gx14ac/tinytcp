// IPv6 header parser (RFC 8200).
// Fixed 40-byte header, extension headers not parsed (treated as payload).

const std = @import("std");

/// Fixed IPv6 header size.
pub const header_len: usize = 40;

/// IPv6 Next Header values (same as IPv4 Protocol for common ones).
pub const NextHeader = enum(u8) {
    hop_by_hop = 0,
    icmpv4 = 1,
    tcp = 6,
    udp = 17,
    routing = 43,
    fragment = 44,
    icmpv6 = 58,
    no_next_header = 59,
    destination = 60,
    _,
};

/// Parsed IPv6 header (view over raw bytes).
pub const Header = struct {
    bytes: []const u8,

    pub fn parse(data: []const u8) error{ TooShort, InvalidVersion }!Header {
        if (data.len < header_len) return error.TooShort;

        const version = data[0] >> 4;
        if (version != 6) return error.InvalidVersion;

        return Header{ .bytes = data[0..header_len] };
    }

    /// Traffic Class (8 bits across bytes 0-1).
    pub fn trafficClass(self: Header) u8 {
        return @intCast(((self.bytes[0] & 0x0F) << 4) | (self.bytes[1] >> 4));
    }

    /// Flow Label (20 bits across bytes 1-3).
    pub fn flowLabel(self: Header) u20 {
        return @intCast((@as(u32, self.bytes[1] & 0x0F) << 16) |
            (@as(u32, self.bytes[2]) << 8) |
            @as(u32, self.bytes[3]));
    }

    /// Payload length (not including the 40-byte header).
    pub fn payloadLen(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[4..6], .big);
    }

    /// Next Header field (protocol of encapsulated data).
    pub fn nextHeader(self: Header) NextHeader {
        return @enumFromInt(self.bytes[6]);
    }

    /// Hop Limit (equivalent to TTL in IPv4).
    pub fn hopLimit(self: Header) u8 {
        return self.bytes[7];
    }

    /// Source address (128 bits).
    pub fn srcAddr(self: Header) [16]u8 {
        return self.bytes[8..24].*;
    }

    /// Destination address (128 bits).
    pub fn dstAddr(self: Header) [16]u8 {
        return self.bytes[24..40].*;
    }

    /// Get the payload slice.
    pub fn payload(self: Header, full_packet: []const u8) []const u8 {
        const plen = @as(usize, self.payloadLen());
        const end = header_len + plen;
        if (full_packet.len < end) {
            return full_packet[header_len..];
        }
        return full_packet[header_len..end];
    }
};

/// Mutable IPv6 header for building packets.
pub const MutableHeader = struct {
    bytes: []u8,

    pub fn init(buf: []u8) error{TooShort}!MutableHeader {
        if (buf.len < header_len) return error.TooShort;
        @memset(buf[0..header_len], 0);
        buf[0] = 0x60; // version=6, traffic class high nibble=0
        return MutableHeader{ .bytes = buf[0..header_len] };
    }

    pub fn setPayloadLen(self: *MutableHeader, len: u16) void {
        std.mem.writeInt(u16, self.bytes[4..6], len, .big);
    }

    pub fn setNextHeader(self: *MutableHeader, nh: NextHeader) void {
        self.bytes[6] = @intFromEnum(nh);
    }

    pub fn setHopLimit(self: *MutableHeader, limit: u8) void {
        self.bytes[7] = limit;
    }

    pub fn setSrcAddr(self: *MutableHeader, addr: [16]u8) void {
        @memcpy(self.bytes[8..24], &addr);
    }

    pub fn setDstAddr(self: *MutableHeader, addr: [16]u8) void {
        @memcpy(self.bytes[24..40], &addr);
    }

    pub fn asConst(self: MutableHeader) Header {
        return Header{ .bytes = self.bytes };
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "ipv6: parse basic header" {
    var pkt: [40]u8 = undefined;
    @memset(&pkt, 0);
    pkt[0] = 0x60; // version 6
    pkt[4] = 0x00;
    pkt[5] = 0x14; // payload len = 20
    pkt[6] = 0x06; // next header = TCP
    pkt[7] = 0x40; // hop limit = 64
    // src: 2001:db8::1
    pkt[8] = 0x20;
    pkt[9] = 0x01;
    pkt[10] = 0x0d;
    pkt[11] = 0xb8;
    pkt[31] = 0x01; // last byte of src (byte index 23 from src start = index 8+15=23... actually src is bytes 8..24)
    // Wait, src is bytes[8..24], so last byte of src is pkt[23]
    pkt[23] = 0x01;
    pkt[31] = 0x00; // reset

    const hdr = try Header.parse(&pkt);
    try testing.expectEqual(@as(u16, 20), hdr.payloadLen());
    try testing.expectEqual(NextHeader.tcp, hdr.nextHeader());
    try testing.expectEqual(@as(u8, 64), hdr.hopLimit());
}

test "ipv6: reject too short" {
    const short = [_]u8{0x60} ++ [_]u8{0} ** 20;
    try testing.expectError(error.TooShort, Header.parse(&short));
}

test "ipv6: reject wrong version" {
    var pkt: [40]u8 = undefined;
    @memset(&pkt, 0);
    pkt[0] = 0x40; // version 4
    try testing.expectError(error.InvalidVersion, Header.parse(&pkt));
}

test "ipv6: mutable build" {
    var buf: [40]u8 = undefined;
    var hdr = try MutableHeader.init(&buf);
    hdr.setPayloadLen(100);
    hdr.setNextHeader(.udp);
    hdr.setHopLimit(128);

    const view = hdr.asConst();
    try testing.expectEqual(@as(u16, 100), view.payloadLen());
    try testing.expectEqual(NextHeader.udp, view.nextHeader());
    try testing.expectEqual(@as(u8, 128), view.hopLimit());
}
