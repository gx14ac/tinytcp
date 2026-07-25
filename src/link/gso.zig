// GSO (Generic Segmentation Offload).
//
// Accepts large writes from the transport layer and defers segmentation
// to the link layer, amortizing header computation across many segments.
//
// The transport layer produces one large "super-segment" which GSO splits
// into MSS-sized packets at send time.
//
// Sans-IO: purely splits buffers; no I/O.

const std = @import("std");

/// Maximum MSS for segmentation.
const default_mss: u16 = 1460;

/// Maximum segments from one GSO split.
pub const max_segments: usize = 64;

/// A segment descriptor produced by GSO.
pub const GsoSegment = struct {
    offset: usize,
    len: usize,
    seq: u32,
    is_last: bool,
};

/// GSO engine — splits a large payload into MSS-sized segments.
pub const Gso = struct {
    mss: u16 = default_mss,

    pub fn init(mss: u16) Gso {
        return .{ .mss = if (mss == 0) default_mss else mss };
    }

    /// Split a large payload into segments.
    /// Returns the number of segments written to `out`.
    /// Each segment descriptor points into the original payload buffer.
    pub fn segment(self: *const Gso, base_seq: u32, payload_len: usize, out: []GsoSegment) usize {
        if (payload_len == 0) return 0;

        const mss_usize: usize = self.mss;
        var offset: usize = 0;
        var count: usize = 0;
        var seq = base_seq;

        while (offset < payload_len and count < out.len) {
            const remaining = payload_len - offset;
            const seg_len = @min(remaining, mss_usize);
            const is_last = (offset + seg_len >= payload_len);

            out[count] = .{
                .offset = offset,
                .len = seg_len,
                .seq = seq,
                .is_last = is_last,
            };

            offset += seg_len;
            seq +%= @intCast(seg_len);
            count += 1;
        }

        return count;
    }

    /// Calculate number of segments needed for a given payload.
    pub fn segmentCount(self: *const Gso, payload_len: usize) usize {
        if (payload_len == 0) return 0;
        return (payload_len + self.mss - 1) / self.mss;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "GSO: exact MSS boundary" {
    const gso = Gso.init(10);
    var segs: [max_segments]GsoSegment = undefined;

    const count = gso.segment(1000, 30, &segs);
    try testing.expectEqual(@as(usize, 3), count);

    try testing.expectEqual(@as(usize, 0), segs[0].offset);
    try testing.expectEqual(@as(usize, 10), segs[0].len);
    try testing.expectEqual(@as(u32, 1000), segs[0].seq);
    try testing.expect(!segs[0].is_last);

    try testing.expectEqual(@as(usize, 10), segs[1].offset);
    try testing.expectEqual(@as(usize, 10), segs[1].len);
    try testing.expectEqual(@as(u32, 1010), segs[1].seq);
    try testing.expect(!segs[1].is_last);

    try testing.expectEqual(@as(usize, 20), segs[2].offset);
    try testing.expectEqual(@as(usize, 10), segs[2].len);
    try testing.expectEqual(@as(u32, 1020), segs[2].seq);
    try testing.expect(segs[2].is_last);
}

test "GSO: partial last segment" {
    const gso = Gso.init(10);
    var segs: [max_segments]GsoSegment = undefined;

    const count = gso.segment(5000, 25, &segs);
    try testing.expectEqual(@as(usize, 3), count);

    try testing.expectEqual(@as(usize, 10), segs[0].len);
    try testing.expectEqual(@as(usize, 10), segs[1].len);
    try testing.expectEqual(@as(usize, 5), segs[2].len);
    try testing.expect(segs[2].is_last);
}

test "GSO: single segment" {
    const gso = Gso.init(1460);
    var segs: [max_segments]GsoSegment = undefined;

    const count = gso.segment(100, 500, &segs);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqual(@as(usize, 500), segs[0].len);
    try testing.expect(segs[0].is_last);
}

test "GSO: empty payload" {
    const gso = Gso.init(1460);
    var segs: [max_segments]GsoSegment = undefined;

    const count = gso.segment(0, 0, &segs);
    try testing.expectEqual(@as(usize, 0), count);
}

test "GSO: segmentCount" {
    const gso = Gso.init(1460);
    try testing.expectEqual(@as(usize, 0), gso.segmentCount(0));
    try testing.expectEqual(@as(usize, 1), gso.segmentCount(1));
    try testing.expectEqual(@as(usize, 1), gso.segmentCount(1460));
    try testing.expectEqual(@as(usize, 2), gso.segmentCount(1461));
    try testing.expectEqual(@as(usize, 10), gso.segmentCount(14600));
}

test "GSO: large payload" {
    const gso = Gso.init(1460);
    var segs: [max_segments]GsoSegment = undefined;

    // 64KB payload → 45 segments
    const count = gso.segment(0, 65536, &segs);
    try testing.expectEqual(@as(usize, 45), count);
    try testing.expect(segs[44].is_last);
    try testing.expectEqual(@as(usize, 65536 - 44 * 1460), segs[44].len);
}
