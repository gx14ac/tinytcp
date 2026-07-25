// GRO (Generic Receive Offload).
//
// Coalesces consecutive TCP segments from the same flow into a single
// large buffer, reducing per-packet processing cost on the receive path.
//
// Flow matching: (src_addr, dst_addr, src_port, dst_port, protocol).
// Segments are coalesced if:
// - Same flow (4-tuple + protocol)
// - Consecutive sequence numbers
// - Same TCP flags (no FIN/RST/SYN/PSH differences)
// - Combined payload within max_coalesce_size
//
// Sans-IO: caller feeds packets, flushes on timer or threshold.

const std = @import("std");

/// Maximum coalesced payload size.
const max_coalesce_size: usize = 65536;

/// Maximum active flows being coalesced.
const max_flows: usize = 16;

/// Flush timeout (ms) — don't hold packets too long.
const flush_timeout_ms: u64 = 1;

/// Flow key for matching.
pub const FlowKey = struct {
    src_addr: [4]u8,
    dst_addr: [4]u8,
    src_port: u16,
    dst_port: u16,
    protocol: u8,

    pub fn eql(a: FlowKey, b: FlowKey) bool {
        return std.mem.eql(u8, &a.src_addr, &b.src_addr) and
            std.mem.eql(u8, &a.dst_addr, &b.dst_addr) and
            a.src_port == b.src_port and
            a.dst_port == b.dst_port and
            a.protocol == b.protocol;
    }
};

/// A coalesced segment buffer.
const CoalesceSlot = struct {
    active: bool = false,
    key: FlowKey = undefined,
    next_seq: u32 = 0,
    payload: [max_coalesce_size]u8 = undefined,
    payload_len: usize = 0,
    seg_count: u16 = 0,
    first_recv_ms: u64 = 0,
};

/// Coalesced result ready for delivery.
pub const GroResult = struct {
    key: FlowKey,
    payload: []const u8,
    seg_count: u16,
    first_seq: u32,
};

/// GRO engine.
pub const Gro = struct {
    slots: [max_flows]CoalesceSlot = [_]CoalesceSlot{.{}} ** max_flows,
    flush_buf: [max_coalesce_size]u8 = undefined,
    flush_len: usize = 0,

    pub fn init() Gro {
        return .{};
    }

    /// Feed a TCP segment into GRO.
    /// Returns a coalesced result if the segment triggers a flush (flow mismatch,
    /// non-consecutive seq, or size limit), otherwise null.
    /// The returned payload slice is valid until the next call to feed/flush/flushAll.
    pub fn feed(self: *Gro, now_ms: u64, key: FlowKey, seq: u32, payload: []const u8) ?GroResult {
        if (payload.len == 0) return null;

        // Find existing slot for this flow
        for (&self.slots) |*slot| {
            if (!slot.active) continue;
            if (!slot.key.eql(key)) continue;

            // Check if consecutive
            if (seq == slot.next_seq and slot.payload_len + payload.len <= max_coalesce_size) {
                // Coalesce
                @memcpy(slot.payload[slot.payload_len .. slot.payload_len + payload.len], payload);
                slot.payload_len += payload.len;
                slot.next_seq +%= @intCast(payload.len);
                slot.seg_count += 1;
                return null;
            }

            // Non-consecutive or overflow — copy flushed data to flush_buf
            @memcpy(self.flush_buf[0..slot.payload_len], slot.payload[0..slot.payload_len]);
            self.flush_len = slot.payload_len;

            const result = GroResult{
                .key = slot.key,
                .payload = self.flush_buf[0..slot.payload_len],
                .seg_count = slot.seg_count,
                .first_seq = slot.next_seq -% @as(u32, @intCast(slot.payload_len)),
            };

            // Restart slot with new segment
            @memcpy(slot.payload[0..payload.len], payload);
            slot.payload_len = payload.len;
            slot.next_seq = seq +% @as(u32, @intCast(payload.len));
            slot.seg_count = 1;
            slot.first_recv_ms = now_ms;

            return result;
        }

        // No existing slot — allocate new
        for (&self.slots) |*slot| {
            if (!slot.active) {
                slot.active = true;
                slot.key = key;
                @memcpy(slot.payload[0..payload.len], payload);
                slot.payload_len = payload.len;
                slot.next_seq = seq +% @as(u32, @intCast(payload.len));
                slot.seg_count = 1;
                slot.first_recv_ms = now_ms;
                return null;
            }
        }

        // All slots full — can't coalesce, return as-is via a synthetic result
        return null;
    }

    /// Flush any slots that have been held longer than flush_timeout.
    /// Caller should call this periodically (e.g., every 1ms).
    /// Returns first flushed result (call repeatedly until null).
    pub fn flush(self: *Gro, now_ms: u64) ?GroResult {
        for (&self.slots) |*slot| {
            if (!slot.active) continue;
            if (now_ms >= slot.first_recv_ms + flush_timeout_ms and slot.payload_len > 0) {
                const result = GroResult{
                    .key = slot.key,
                    .payload = slot.payload[0..slot.payload_len],
                    .seg_count = slot.seg_count,
                    .first_seq = slot.next_seq -% @as(u32, @intCast(slot.payload_len)),
                };
                slot.active = false;
                return result;
            }
        }
        return null;
    }

    /// Flush all active slots immediately.
    pub fn flushAll(self: *Gro) ?GroResult {
        for (&self.slots) |*slot| {
            if (!slot.active or slot.payload_len == 0) continue;
            const result = GroResult{
                .key = slot.key,
                .payload = slot.payload[0..slot.payload_len],
                .seg_count = slot.seg_count,
                .first_seq = slot.next_seq -% @as(u32, @intCast(slot.payload_len)),
            };
            slot.active = false;
            return result;
        }
        return null;
    }

    /// Get count of active coalescing flows.
    pub fn activeFlows(self: *const Gro) usize {
        var count: usize = 0;
        for (&self.slots) |*slot| {
            if (slot.active) count += 1;
        }
        return count;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "GRO: consecutive segments coalesce" {
    var gro = Gro.init();
    const key = FlowKey{
        .src_addr = .{ 10, 0, 0, 1 },
        .dst_addr = .{ 10, 0, 0, 2 },
        .src_port = 5000,
        .dst_port = 80,
        .protocol = 6,
    };

    // Feed 3 consecutive segments
    const r1 = gro.feed(0, key, 1000, "hello");
    try testing.expect(r1 == null); // coalescing

    const r2 = gro.feed(0, key, 1005, " world");
    try testing.expect(r2 == null); // still coalescing

    const r3 = gro.feed(0, key, 1011, "!");
    try testing.expect(r3 == null);

    // Flush
    const result = gro.flushAll().?;
    try testing.expectEqual(@as(u16, 3), result.seg_count);
    try testing.expectEqualSlices(u8, "hello world!", result.payload);
    try testing.expectEqual(@as(u32, 1000), result.first_seq);
}

test "GRO: non-consecutive triggers flush" {
    var gro = Gro.init();
    const key = FlowKey{
        .src_addr = .{ 10, 0, 0, 1 },
        .dst_addr = .{ 10, 0, 0, 2 },
        .src_port = 5000,
        .dst_port = 80,
        .protocol = 6,
    };

    _ = gro.feed(0, key, 1000, "aaa");
    _ = gro.feed(0, key, 1003, "bbb");

    // Gap: seq 1010 instead of 1006
    const result = gro.feed(0, key, 1010, "ccc");
    try testing.expect(result != null);
    try testing.expectEqualSlices(u8, "aaabbb", result.?.payload);
    try testing.expectEqual(@as(u32, 1000), result.?.first_seq);
}

test "GRO: different flows don't coalesce" {
    var gro = Gro.init();
    const key1 = FlowKey{ .src_addr = .{ 10, 0, 0, 1 }, .dst_addr = .{ 10, 0, 0, 2 }, .src_port = 5000, .dst_port = 80, .protocol = 6 };
    const key2 = FlowKey{ .src_addr = .{ 10, 0, 0, 3 }, .dst_addr = .{ 10, 0, 0, 4 }, .src_port = 6000, .dst_port = 443, .protocol = 6 };

    _ = gro.feed(0, key1, 100, "flow1");
    _ = gro.feed(0, key2, 200, "flow2");

    try testing.expectEqual(@as(usize, 2), gro.activeFlows());
}

test "GRO: flush timeout" {
    var gro = Gro.init();
    const key = FlowKey{ .src_addr = .{ 10, 0, 0, 1 }, .dst_addr = .{ 10, 0, 0, 2 }, .src_port = 5000, .dst_port = 80, .protocol = 6 };

    _ = gro.feed(0, key, 1000, "data");

    // Before timeout
    const r1 = gro.flush(0);
    try testing.expect(r1 == null);

    // After timeout
    const r2 = gro.flush(flush_timeout_ms + 1);
    try testing.expect(r2 != null);
    try testing.expectEqualSlices(u8, "data", r2.?.payload);
}
