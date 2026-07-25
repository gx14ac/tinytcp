// IPv4 header parser/serializer (RFC 791).
// Zero-copy: works on borrowed byte slices.

const std = @import("std");
const checksum = @import("../checksum.zig");

/// Minimum IPv4 header size (no options).
pub const min_header_len: usize = 20;

/// Maximum IPv4 header size (with max options).
pub const max_header_len: usize = 60;

/// Maximum total IPv4 packet size.
pub const max_packet_len: usize = 65535;

/// IPv4 protocol numbers.
pub const Protocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    icmpv6 = 58,
    _,
};

/// Parsed IPv4 header (view over raw bytes).
pub const Header = struct {
    bytes: []const u8,

    pub fn parse(data: []const u8) error{ TooShort, InvalidVersion, InvalidIhl }!Header {
        if (data.len < min_header_len) return error.TooShort;

        const version = data[0] >> 4;
        if (version != 4) return error.InvalidVersion;

        const ihl = data[0] & 0x0F;
        if (ihl < 5) return error.InvalidIhl;

        const header_len = @as(usize, ihl) * 4;
        if (data.len < header_len) return error.TooShort;

        return Header{ .bytes = data[0..header_len] };
    }

    /// Internet Header Length in bytes.
    pub fn headerLen(self: Header) usize {
        return @as(usize, self.bytes[0] & 0x0F) * 4;
    }

    /// Total length of IP datagram (header + payload).
    pub fn totalLen(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[2..4], .big);
    }

    /// Payload length (total - header).
    pub fn payloadLen(self: Header) u16 {
        return self.totalLen() -| @as(u16, @intCast(self.headerLen()));
    }

    /// Type of Service / DSCP + ECN.
    pub fn tos(self: Header) u8 {
        return self.bytes[1];
    }

    /// ECN field (low 2 bits of TOS): 0=not-ECT, 1=ECT(1), 2=ECT(0), 3=CE.
    pub fn ecn(self: Header) u2 {
        return @truncate(self.bytes[1] & 0x03);
    }

    /// Identification field.
    pub fn identification(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[4..6], .big);
    }

    /// Flags (3 bits).
    pub fn flags(self: Header) u3 {
        return @intCast(self.bytes[6] >> 5);
    }

    /// Don't Fragment flag.
    pub fn dontFragment(self: Header) bool {
        return (self.bytes[6] & 0x40) != 0;
    }

    /// More Fragments flag.
    pub fn moreFragments(self: Header) bool {
        return (self.bytes[6] & 0x20) != 0;
    }

    /// Fragment offset (in 8-byte units).
    pub fn fragmentOffset(self: Header) u13 {
        return @intCast((@as(u16, self.bytes[6] & 0x1F) << 8) | @as(u16, self.bytes[7]));
    }

    /// Time to Live.
    pub fn ttl(self: Header) u8 {
        return self.bytes[8];
    }

    /// Protocol number.
    pub fn protocol(self: Header) Protocol {
        return @enumFromInt(self.bytes[9]);
    }

    /// Header checksum.
    pub fn headerChecksum(self: Header) u16 {
        return std.mem.readInt(u16, self.bytes[10..12], .big);
    }

    /// Source IP address.
    pub fn srcAddr(self: Header) [4]u8 {
        return self.bytes[12..16].*;
    }

    /// Destination IP address.
    pub fn dstAddr(self: Header) [4]u8 {
        return self.bytes[16..20].*;
    }

    /// Options bytes (empty if IHL == 5).
    pub fn options(self: Header) []const u8 {
        if (self.headerLen() > min_header_len) {
            return self.bytes[min_header_len..self.headerLen()];
        }
        return &.{};
    }

    /// Verify the header checksum.
    pub fn isChecksumValid(self: Header) bool {
        return checksum.verify(self.bytes);
    }

    /// Get the payload slice (data after the header within total_len).
    pub fn payload(self: Header, full_packet: []const u8) []const u8 {
        const hlen = self.headerLen();
        const tlen = @as(usize, self.totalLen());
        if (full_packet.len < tlen) {
            return full_packet[hlen..];
        }
        return full_packet[hlen..tlen];
    }
};

/// Mutable IPv4 header for building/modifying packets.
pub const MutableHeader = struct {
    bytes: []u8,

    /// Initialize a new IPv4 header with defaults.
    pub fn init(buf: []u8) error{TooShort}!MutableHeader {
        if (buf.len < min_header_len) return error.TooShort;
        @memset(buf[0..min_header_len], 0);
        buf[0] = 0x45; // version=4, IHL=5
        return MutableHeader{ .bytes = buf[0..min_header_len] };
    }

    /// Set ECN field (low 2 bits of TOS byte), preserving DSCP.
    pub fn setEcn(self: *MutableHeader, ecn: u2) void {
        self.bytes[1] = (self.bytes[1] & 0xFC) | @as(u8, ecn);
    }

    pub fn setTotalLen(self: *MutableHeader, len: u16) void {
        std.mem.writeInt(u16, self.bytes[2..4], len, .big);
    }

    pub fn setIdentification(self: *MutableHeader, id: u16) void {
        std.mem.writeInt(u16, self.bytes[4..6], id, .big);
    }

    pub fn setDontFragment(self: *MutableHeader) void {
        self.bytes[6] |= 0x40;
    }

    pub fn setTtl(self: *MutableHeader, ttl_val: u8) void {
        self.bytes[8] = ttl_val;
    }

    pub fn setProtocol(self: *MutableHeader, proto: Protocol) void {
        self.bytes[9] = @intFromEnum(proto);
    }

    pub fn setSrcAddr(self: *MutableHeader, addr: [4]u8) void {
        @memcpy(self.bytes[12..16], &addr);
    }

    pub fn setDstAddr(self: *MutableHeader, addr: [4]u8) void {
        @memcpy(self.bytes[16..20], &addr);
    }

    /// Compute and write the header checksum.
    pub fn computeChecksum(self: *MutableHeader) void {
        // Clear existing checksum
        self.bytes[10] = 0;
        self.bytes[11] = 0;
        const cksum = checksum.compute(self.bytes);
        std.mem.writeInt(u16, self.bytes[10..12], cksum, .big);
    }

    /// Get an immutable view.
    pub fn asConst(self: MutableHeader) Header {
        return Header{ .bytes = self.bytes };
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "ipv4: parse minimal header" {
    // Minimal valid IPv4 header (20 bytes)
    var pkt = [_]u8{
        0x45, 0x00, 0x00, 0x28, // version=4, IHL=5, total=40
        0x00, 0x01, 0x40, 0x00, // ID=1, DF=1
        0x40, 0x06, 0x00, 0x00, // TTL=64, proto=TCP, checksum=0
        0xC0, 0xA8, 0x01, 0x01, // src=192.168.1.1
        0xC0, 0xA8, 0x01, 0x02, // dst=192.168.1.2
    };
    // Compute valid checksum
    const cksum = checksum.compute(&pkt);
    pkt[10] = @intCast(cksum >> 8);
    pkt[11] = @intCast(cksum & 0xFF);

    const hdr = try Header.parse(&pkt);
    try testing.expectEqual(@as(usize, 20), hdr.headerLen());
    try testing.expectEqual(@as(u16, 40), hdr.totalLen());
    try testing.expectEqual(@as(u8, 64), hdr.ttl());
    try testing.expectEqual(Protocol.tcp, hdr.protocol());
    try testing.expect(hdr.dontFragment());
    try testing.expect(!hdr.moreFragments());
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, &hdr.srcAddr());
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 2 }, &hdr.dstAddr());
    try testing.expect(hdr.isChecksumValid());
}

test "ipv4: reject too short" {
    const short = [_]u8{ 0x45, 0x00, 0x00 };
    try testing.expectError(error.TooShort, Header.parse(&short));
}

test "ipv4: reject wrong version" {
    var pkt = [_]u8{0} ** 20;
    pkt[0] = 0x65; // version=6
    try testing.expectError(error.InvalidVersion, Header.parse(&pkt));
}

test "ipv4: mutable header build" {
    var buf: [20]u8 = undefined;
    var hdr = try MutableHeader.init(&buf);
    hdr.setTotalLen(40);
    hdr.setTtl(64);
    hdr.setProtocol(.tcp);
    hdr.setSrcAddr(.{ 10, 0, 0, 1 });
    hdr.setDstAddr(.{ 10, 0, 0, 2 });
    hdr.setDontFragment();
    hdr.computeChecksum();

    const view = hdr.asConst();
    try testing.expectEqual(@as(u16, 40), view.totalLen());
    try testing.expectEqual(@as(u8, 64), view.ttl());
    try testing.expect(view.dontFragment());
    try testing.expect(view.isChecksumValid());
}
