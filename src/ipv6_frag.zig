// IPv6 Fragmentation (RFC 8200 §4.5).
//
// In IPv6, only the source fragments — intermediate routers never fragment.
// Fragment Header (Next Header = 44):
//   Next Header(1) + Reserved(1) + Fragment Offset(13) + Res(2) + M flag(1) + Identification(4)
//
// Reassembly with 60s timeout (RFC 8200 §4.5).
//
// Sans-IO: no I/O; produces fragment packets and reassembles incoming.

const std = @import("std");
const ipv6_header = @import("header/ipv6.zig");

/// Fragment extension header size.
pub const frag_hdr_len: usize = 8;

/// Maximum reassembly flows.
const max_flows: usize = 8;

/// Maximum payload size per reassembled datagram.
const max_payload: usize = 8192;

/// Reassembly timeout (ms) — RFC 8200 mandates 60 seconds.
const reassembly_timeout_ms: u64 = 60_000;

/// IPv6 Fragment Header.
pub const FragHeader = struct {
    next_header: ipv6_header.NextHeader,
    frag_offset: u13,
    more_fragments: bool,
    identification: u32,

    pub fn parse(data: []const u8) ?FragHeader {
        if (data.len < frag_hdr_len) return null;
        const offset_flags = std.mem.readInt(u16, data[2..4], .big);
        return FragHeader{
            .next_header = @enumFromInt(data[0]),
            .frag_offset = @intCast(offset_flags >> 3),
            .more_fragments = (offset_flags & 1) != 0,
            .identification = std.mem.readInt(u32, data[4..8], .big),
        };
    }

    pub fn serialize(self: *const FragHeader, out: []u8) void {
        if (out.len < frag_hdr_len) return;
        out[0] = @intFromEnum(self.next_header);
        out[1] = 0; // reserved
        const offset_flags: u16 = (@as(u16, self.frag_offset) << 3) | @as(u16, if (self.more_fragments) 1 else 0);
        std.mem.writeInt(u16, out[2..4], offset_flags, .big);
        std.mem.writeInt(u32, out[4..8], self.identification, .big);
    }
};

/// Reassembly flow slot.
const ReasmFlow = struct {
    active: bool = false,
    src: [16]u8 = .{0} ** 16,
    dst: [16]u8 = .{0} ** 16,
    identification: u32 = 0,
    next_header: ipv6_header.NextHeader = .no_next_header,
    received_ms: u64 = 0,
    total_len: usize = 0,
    have_last: bool = false,
    bitmap: [max_payload / 8]u1 = .{0} ** (max_payload / 8),
    data: [max_payload]u8 = undefined,
    bytes_received: usize = 0,
};

/// Reassembly result.
pub const ReasmResult = struct {
    next_header: ipv6_header.NextHeader,
    src: [16]u8,
    dst: [16]u8,
    data: []const u8,
    slot_idx: usize,
};

/// IPv6 fragment reassembler.
pub const Reassembler = struct {
    flows: [max_flows]ReasmFlow = [_]ReasmFlow{.{}} ** max_flows,

    /// Inject a fragment. Returns reassembled payload when complete.
    /// `raw` is the full IPv6 packet (with fragment extension header).
    pub fn inject(self: *Reassembler, now_ms: u64, raw: []const u8) ?ReasmResult {
        if (raw.len < ipv6_header.header_len + frag_hdr_len) return null;

        const ip6 = ipv6_header.Header.parse(raw) catch return null;
        if (ip6.nextHeader() != .fragment) return null;

        const frag_start = ipv6_header.header_len;
        const fh = FragHeader.parse(raw[frag_start..]) orelse return null;

        const src = ip6.srcAddr();
        const dst = ip6.dstAddr();

        // Find or allocate flow
        const slot_idx = self.findOrAllocFlow(now_ms, src, dst, fh.identification, fh.next_header) orelse return null;
        const flow = &self.flows[slot_idx];

        // Fragment data starts after IPv6 header + fragment header
        const data_start = ipv6_header.header_len + frag_hdr_len;
        if (raw.len <= data_start) return null;
        const frag_data = raw[data_start..];

        const offset_bytes = @as(usize, fh.frag_offset) * 8;
        const end = offset_bytes + frag_data.len;
        if (end > max_payload) return null;

        // Copy data
        @memcpy(flow.data[offset_bytes..end], frag_data);

        // Mark bitmap
        const block_start = offset_bytes / 8;
        const block_end = (end + 7) / 8;
        var b: usize = block_start;
        while (b < block_end and b < flow.bitmap.len) : (b += 1) {
            flow.bitmap[b] = 1;
        }
        flow.bytes_received += frag_data.len;

        if (!fh.more_fragments) {
            flow.have_last = true;
            flow.total_len = end;
        }

        // Check if reassembly complete
        if (flow.have_last) {
            const total_blocks = (flow.total_len + 7) / 8;
            var complete = true;
            var i: usize = 0;
            while (i < total_blocks) : (i += 1) {
                if (flow.bitmap[i] != 1) {
                    complete = false;
                    break;
                }
            }
            if (complete) {
                return ReasmResult{
                    .next_header = flow.next_header,
                    .src = flow.src,
                    .dst = flow.dst,
                    .data = flow.data[0..flow.total_len],
                    .slot_idx = slot_idx,
                };
            }
        }

        return null;
    }

    /// Release a reassembly slot after consuming the result.
    pub fn release(self: *Reassembler, slot_idx: usize) void {
        if (slot_idx < max_flows) {
            self.flows[slot_idx].active = false;
        }
    }

    /// Expire old flows.
    pub fn tick(self: *Reassembler, now_ms: u64) void {
        for (&self.flows) |*f| {
            if (f.active and now_ms >= f.received_ms + reassembly_timeout_ms) {
                f.active = false;
            }
        }
    }

    fn findOrAllocFlow(self: *Reassembler, now_ms: u64, src: [16]u8, dst: [16]u8, id: u32, next_hdr: ipv6_header.NextHeader) ?usize {
        // Find existing
        for (&self.flows, 0..) |*f, i| {
            if (f.active and f.identification == id and
                std.mem.eql(u8, &f.src, &src) and std.mem.eql(u8, &f.dst, &dst))
            {
                return i;
            }
        }
        // Allocate new
        for (&self.flows, 0..) |*f, i| {
            if (!f.active) {
                f.* = .{
                    .active = true,
                    .src = src,
                    .dst = dst,
                    .identification = id,
                    .next_header = next_hdr,
                    .received_ms = now_ms,
                };
                return i;
            }
        }
        // Evict oldest
        var oldest_idx: usize = 0;
        var oldest_ts: u64 = std.math.maxInt(u64);
        for (&self.flows, 0..) |*f, i| {
            if (f.received_ms < oldest_ts) {
                oldest_ts = f.received_ms;
                oldest_idx = i;
            }
        }
        self.flows[oldest_idx] = .{
            .active = true,
            .src = src,
            .dst = dst,
            .identification = id,
            .next_header = next_hdr,
            .received_ms = now_ms,
        };
        return oldest_idx;
    }
};

/// Fragment an IPv6 payload into multiple fragments.
/// `payload` is the upper-layer data (e.g. TCP segment).
/// `mtu` is the path MTU.
/// Returns slices via callback.
pub const Fragmenter = struct {
    id_counter: u32 = 1,

    /// Fragment a packet. Calls `emit` for each fragment.
    /// Returns number of fragments emitted.
    pub fn fragment(
        self: *Fragmenter,
        src: [16]u8,
        dst: [16]u8,
        next_header: ipv6_header.NextHeader,
        payload: []const u8,
        mtu: u16,
        out_buf: []u8,
        out_sizes: []usize,
    ) usize {
        const ip6_hlen = ipv6_header.header_len;
        const overhead = ip6_hlen + frag_hdr_len;
        if (mtu <= overhead) return 0;

        // Max fragment payload must be multiple of 8
        const max_frag_payload = ((@as(usize, mtu) - overhead) / 8) * 8;
        if (max_frag_payload == 0) return 0;

        const id = self.id_counter;
        self.id_counter +%= 1;

        var offset: usize = 0;
        var frag_count: usize = 0;
        var buf_offset: usize = 0;

        while (offset < payload.len) {
            const remaining = payload.len - offset;
            const frag_payload_len = @min(remaining, max_frag_payload);
            const is_last = (offset + frag_payload_len >= payload.len);
            const pkt_len = overhead + frag_payload_len;

            if (buf_offset + pkt_len > out_buf.len) break;
            if (frag_count >= out_sizes.len) break;

            const pkt = out_buf[buf_offset .. buf_offset + pkt_len];

            // IPv6 header
            var ip6 = ipv6_header.MutableHeader.init(pkt[0..ip6_hlen]) catch break;
            ip6.setPayloadLen(@intCast(frag_hdr_len + frag_payload_len));
            ip6.setNextHeader(.fragment);
            ip6.setHopLimit(64);
            ip6.setSrcAddr(src);
            ip6.setDstAddr(dst);

            // Fragment header
            const fh = FragHeader{
                .next_header = next_header,
                .frag_offset = @intCast(offset / 8),
                .more_fragments = !is_last,
                .identification = id,
            };
            fh.serialize(pkt[ip6_hlen .. ip6_hlen + frag_hdr_len]);

            // Payload
            @memcpy(pkt[overhead .. overhead + frag_payload_len], payload[offset .. offset + frag_payload_len]);

            out_sizes[frag_count] = pkt_len;
            frag_count += 1;
            buf_offset += pkt_len;
            offset += frag_payload_len;
        }

        return frag_count;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "FragHeader: parse and serialize" {
    var buf: [8]u8 = undefined;
    const fh = FragHeader{
        .next_header = .tcp,
        .frag_offset = 100,
        .more_fragments = true,
        .identification = 0x12345678,
    };
    fh.serialize(&buf);

    const parsed = FragHeader.parse(&buf).?;
    try testing.expectEqual(ipv6_header.NextHeader.tcp, parsed.next_header);
    try testing.expectEqual(@as(u13, 100), parsed.frag_offset);
    try testing.expect(parsed.more_fragments);
    try testing.expectEqual(@as(u32, 0x12345678), parsed.identification);
}

test "Fragmenter: small payload no fragmentation needed" {
    var frag = Fragmenter{};
    const src = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    const payload = "Hello, IPv6!";

    var out_buf: [2048]u8 = undefined;
    var out_sizes: [10]usize = undefined;

    const count = frag.fragment(src, dst, .tcp, payload, 1280, &out_buf, &out_sizes);
    // Payload (12 bytes) + overhead (48) = 60 < 1280, so 1 fragment
    try testing.expectEqual(@as(usize, 1), count);

    // Verify the fragment
    const pkt = out_buf[0..out_sizes[0]];
    try testing.expectEqual(@as(usize, 40 + 8 + 12), pkt.len);

    // Parse fragment header
    const fh = FragHeader.parse(pkt[40..48]).?;
    try testing.expectEqual(ipv6_header.NextHeader.tcp, fh.next_header);
    try testing.expectEqual(@as(u13, 0), fh.frag_offset);
    try testing.expect(!fh.more_fragments); // last fragment
}

test "Fragmenter: large payload needs multiple fragments" {
    var frag = Fragmenter{};
    const src = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

    // 2000 bytes of payload with MTU=1280
    // Max frag payload per fragment = (1280 - 48) / 8 * 8 = 1232
    // Two fragments: 1232 + 768 = 2000
    var payload: [2000]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i % 256);

    var out_buf: [4096]u8 = undefined;
    var out_sizes: [10]usize = undefined;

    const count = frag.fragment(src, dst, .udp, &payload, 1280, &out_buf, &out_sizes);
    try testing.expectEqual(@as(usize, 2), count);

    // First fragment: should have M=1
    const fh1 = FragHeader.parse(out_buf[40..48]).?;
    try testing.expectEqual(@as(u13, 0), fh1.frag_offset);
    try testing.expect(fh1.more_fragments);
    try testing.expectEqual(ipv6_header.NextHeader.udp, fh1.next_header);

    // Second fragment: offset = 1232/8 = 154, M=0
    const off2 = out_sizes[0];
    const fh2 = FragHeader.parse(out_buf[off2 + 40 .. off2 + 48]).?;
    try testing.expectEqual(@as(u13, 154), fh2.frag_offset);
    try testing.expect(!fh2.more_fragments);
}

test "Reassembler: two fragments reassemble" {
    var reasm = Reassembler{};
    const src = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

    // Fragment 1: offset=0, M=1, 16 bytes of data
    var frag1: [40 + 8 + 16]u8 = undefined;
    {
        var ip6 = ipv6_header.MutableHeader.init(frag1[0..40]) catch unreachable;
        ip6.setPayloadLen(8 + 16);
        ip6.setNextHeader(.fragment);
        ip6.setHopLimit(64);
        ip6.setSrcAddr(src);
        ip6.setDstAddr(dst);
        const fh = FragHeader{ .next_header = .tcp, .frag_offset = 0, .more_fragments = true, .identification = 42 };
        fh.serialize(frag1[40..48]);
        @memset(frag1[48..64], 0xAA);
    }

    const r1 = reasm.inject(0, &frag1);
    try testing.expect(r1 == null); // not complete yet

    // Fragment 2: offset=16/8=2, M=0, 8 bytes of data
    var frag2: [40 + 8 + 8]u8 = undefined;
    {
        var ip6 = ipv6_header.MutableHeader.init(frag2[0..40]) catch unreachable;
        ip6.setPayloadLen(8 + 8);
        ip6.setNextHeader(.fragment);
        ip6.setHopLimit(64);
        ip6.setSrcAddr(src);
        ip6.setDstAddr(dst);
        const fh = FragHeader{ .next_header = .tcp, .frag_offset = 2, .more_fragments = false, .identification = 42 };
        fh.serialize(frag2[40..48]);
        @memset(frag2[48..56], 0xBB);
    }

    const r2 = reasm.inject(0, &frag2);
    try testing.expect(r2 != null);

    const result = r2.?;
    try testing.expectEqual(@as(usize, 24), result.data.len);
    try testing.expectEqual(ipv6_header.NextHeader.tcp, result.next_header);
    // First 16 bytes should be 0xAA, last 8 should be 0xBB
    for (result.data[0..16]) |b| try testing.expectEqual(@as(u8, 0xAA), b);
    for (result.data[16..24]) |b| try testing.expectEqual(@as(u8, 0xBB), b);

    reasm.release(result.slot_idx);
}

test "Reassembler: timeout expires flow" {
    var reasm = Reassembler{};
    const src = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

    // Inject one fragment
    var frag1: [40 + 8 + 8]u8 = undefined;
    {
        var ip6 = ipv6_header.MutableHeader.init(frag1[0..40]) catch unreachable;
        ip6.setPayloadLen(8 + 8);
        ip6.setNextHeader(.fragment);
        ip6.setHopLimit(64);
        ip6.setSrcAddr(src);
        ip6.setDstAddr(dst);
        const fh = FragHeader{ .next_header = .udp, .frag_offset = 0, .more_fragments = true, .identification = 99 };
        fh.serialize(frag1[40..48]);
        @memset(frag1[48..56], 0xCC);
    }
    _ = reasm.inject(0, &frag1);

    // Flow should be active
    try testing.expect(reasm.flows[0].active);

    // Tick past timeout
    reasm.tick(reassembly_timeout_ms + 1);
    try testing.expect(!reasm.flows[0].active);
}
