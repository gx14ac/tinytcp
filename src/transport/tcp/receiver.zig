// TCP Receiver: manages the receive-side of a TCP connection.
//
// Responsibilities:
// - In-order delivery to application receive buffer
// - Out-of-order (OOO) segment reassembly
// - Receive window management
// - Delayed ACK triggering
// - SACK block generation (future)
//
// Sans-IO: no I/O, caller drives segment delivery.

const std = @import("std");
const endpoint_mod = @import("endpoint.zig");
const config_mod = @import("../../config.zig");
pub const Config = config_mod.Config;

const seqLt = endpoint_mod.seqLt;
const seqLte = endpoint_mod.seqLte;
const seqGt = endpoint_mod.seqGt;

/// Maximum SACK blocks reported.
pub const max_sack_blocks: usize = 4;

/// An out-of-order segment descriptor.
pub const OooSegment = struct {
    /// Starting sequence number.
    start: u32 = 0,
    /// Ending sequence number (exclusive).
    end: u32 = 0,
    /// Whether this slot is in use.
    active: bool = false,
};

/// SACK block (left edge, right edge).
pub const SackBlock = struct {
    left: u32,
    right: u32,
};

/// Receive window auto-tuning state.
/// Note: default field values here are overridden by ReceiverWith's initializer
/// which applies Config values. Do not use .{} directly — use ReceiverWith(cfg).
pub const WindowAutoTune = struct {
    /// Whether auto-tuning is enabled.
    enabled: bool = true,
    /// Current target buffer size (grows based on throughput).
    target_buf: usize = 65536,
    /// Bytes delivered since last measurement.
    bytes_since_measure: usize = 0,
    /// Timestamp of last measurement.
    last_measure_ms: u64 = 0,
    /// Measured throughput (bytes/s).
    throughput_bps: usize = 0,
    /// Estimated BDP (bandwidth * delay product).
    bdp: usize = 0,
    /// Minimum buffer (initial).
    min_buf: usize = 65536,
    /// Maximum buffer (cap).
    max_buf: usize = 512 * 1024,

    /// Update auto-tune on data delivery.
    pub fn onDataDelivered(self: *WindowAutoTune, now_ms: u64, bytes: usize, rtt_ms: u64) void {
        if (!self.enabled) return;
        self.bytes_since_measure += bytes;

        const elapsed = if (now_ms > self.last_measure_ms) now_ms - self.last_measure_ms else 0;
        if (elapsed < 200) return; // Measure every 200ms

        if (elapsed > 0) {
            self.throughput_bps = self.bytes_since_measure * 1000 / @as(usize, @intCast(elapsed));
        }

        // BDP = throughput * RTT
        if (rtt_ms > 0) {
            self.bdp = self.throughput_bps * @as(usize, @intCast(rtt_ms)) / 1000;
        }

        // Target = 2 * BDP (headroom for bursts)
        const target = @max(self.bdp * 2, self.min_buf);
        self.target_buf = @min(target, self.max_buf);

        self.bytes_since_measure = 0;
        self.last_measure_ms = now_ms;
    }
};

/// Default Receiver (uses Config.default — backwards-compatible).
pub const Receiver = ReceiverWith(.{});

/// Configurable TCP Receiver parameterized by comptime Config.
pub fn ReceiverWith(comptime cfg: Config) type {
    return struct {
        const Self = @This();

        const recv_buf_size = cfg.recv_buf_size;
        const max_ooo = cfg.max_ooo_segments;

        /// Next expected sequence number (left edge of receive window).
        rcv_nxt: u32 = 0,
        /// Receive window size in bytes.
        rcv_wnd: u32 = @intCast(@min(cfg.recv_buf_size, std.math.maxInt(u32))),
        /// Initial receive sequence number.
        irs: u32 = 0,

        /// Receive buffer.
        buf: [recv_buf_size]u8 = undefined,
        /// Number of valid bytes in the buffer.
        buf_len: usize = 0,
        /// Buffer capacity.
        buf_cap: usize = recv_buf_size,

        /// Window auto-tuning.
        auto_tune: WindowAutoTune = .{
            .enabled = cfg.auto_tune_enabled,
            .target_buf = cfg.auto_tune_min_buf,
            .min_buf = cfg.auto_tune_min_buf,
            .max_buf = cfg.auto_tune_max_buf,
        },

        /// Out-of-order segment tracking.
        ooo: [max_ooo]OooSegment = [_]OooSegment{.{}} ** max_ooo,

        /// Whether we need to send an ACK (immediate or delayed).
        ack_needed: bool = false,
        /// Whether the ACK should be immediate (e.g., out-of-order received).
        immediate_ack: bool = false,
        /// Whether FIN has been received.
        fin_received: bool = false,
        /// FIN sequence number (the seq of the FIN byte itself).
        fin_seq: u32 = 0,

        /// SACK permitted (negotiated during handshake).
        sack_permitted: bool = false,

        /// Initialize receiver with initial receive sequence number.
        pub fn init(irs: u32, win_size: u32) Self {
            return Self{
                .rcv_nxt = irs +% 1, // After SYN is consumed
                .rcv_wnd = win_size,
                .irs = irs,
            };
        }

        /// Process incoming data segment.
        /// Returns number of new in-order bytes delivered to the buffer.
        pub fn onSegment(self: *Self, seg_seq: u32, payload: []const u8) usize {
            if (payload.len == 0) return 0;

            const seg_end = seg_seq +% @as(u32, @intCast(payload.len));

            // Check if segment is within receive window
            if (!self.inWindow(seg_seq, seg_end)) return 0;

            // Case 1: segment starts at rcv_nxt (in-order)
            if (seg_seq == self.rcv_nxt) {
                const delivered = self.deliverInOrder(payload);
                // Try to fill from OOO segments
                _ = self.reassemble();
                self.ack_needed = true;
                return delivered;
            }

            // Case 2: segment starts before rcv_nxt (partial overlap)
            if (seqLt(seg_seq, self.rcv_nxt)) {
                // Calculate how much of this segment is new
                const overlap = @as(usize, @intCast(@as(u32, @bitCast(@as(i32, @bitCast(self.rcv_nxt -% seg_seq))))));
                if (overlap >= payload.len) return 0; // entirely old
                const new_data = payload[overlap..];
                const delivered = self.deliverInOrder(new_data);
                _ = self.reassemble();
                self.ack_needed = true;
                return delivered;
            }

            // Case 3: out-of-order segment (seg_seq > rcv_nxt)
            self.insertOoo(seg_seq, seg_end, payload);
            self.ack_needed = true;
            self.immediate_ack = true; // OOO → immediate ACK (RFC 5681)
            return 0;
        }

        /// Process a FIN.
        pub fn onFin(self: *Self, fin_seq: u32) void {
            self.fin_received = true;
            self.fin_seq = fin_seq;
            // If FIN is in-order, advance rcv_nxt
            if (fin_seq == self.rcv_nxt) {
                self.rcv_nxt +%= 1;
            }
            self.ack_needed = true;
            self.immediate_ack = true;
        }

        /// Read data from the receive buffer (application call).
        /// Returns number of bytes copied to `dst`.
        pub fn read(self: *Self, dst: []u8) usize {
            const copy_len = @min(dst.len, self.buf_len);
            if (copy_len == 0) return 0;

            @memcpy(dst[0..copy_len], self.buf[0..copy_len]);

            // Shift what is left forward — including the bytes held past
            // buf_len for segments that arrived out of order, which are
            // addressed from buf_len and would otherwise be left behind
            // while everything around them moved.
            const held = self.buf_len + self.oooSpan();
            if (copy_len < held) {
                std.mem.copyForwards(u8, self.buf[0 .. held - copy_len], self.buf[copy_len..held]);
            }
            self.buf_len -= copy_len;

            // Grow window
            self.rcv_wnd += @intCast(copy_len);
            return copy_len;
        }

        /// Get available receive buffer space.
        pub fn available(self: *const Self) usize {
            return self.buf_cap - self.buf_len;
        }

        /// Get current receive window as raw u32 (before scaling).
        /// Implements SWS avoidance (RFC 1122 4.2.3.3): don't advertise
        /// small window increases until at least MSS or half-buffer is free.
        /// When auto-tuning is enabled, advertises up to target_buf.
        pub fn windowRaw(self: *const Self) u32 {
            const effective_cap = if (self.auto_tune.enabled)
                @min(self.auto_tune.target_buf, self.buf_cap)
            else
                self.buf_cap;
            const free = effective_cap -| self.buf_len;
            const threshold = @min(@as(usize, 1460), effective_cap / 2);
            const effective: u32 = if (free < threshold) 0 else @intCast(@min(free, std.math.maxInt(u32)));
            return effective;
        }

        /// Get current receive window clamped to u16 (for unscaled connections).
        pub fn window(self: *const Self) u16 {
            const raw = self.windowRaw();
            return @intCast(@min(raw, 65535));
        }

        /// Update window auto-tuning (call on data delivery with current RTT estimate).
        pub fn updateAutoTune(self: *Self, now_ms: u64, bytes_delivered: usize, rtt_ms: u64) void {
            self.auto_tune.onDataDelivered(now_ms, bytes_delivered, rtt_ms);
        }

        /// Check and clear ACK needed flag.
        pub fn consumeAckNeeded(self: *Self) bool {
            const needed = self.ack_needed;
            self.ack_needed = false;
            self.immediate_ack = false;
            return needed;
        }

        /// Generate SACK blocks from OOO segments.
        pub fn sackBlocks(self: *const Self) [max_sack_blocks]?SackBlock {
            var blocks: [max_sack_blocks]?SackBlock = .{ null, null, null, null };
            var count: usize = 0;

            for (&self.ooo) |*seg| {
                if (seg.active and count < max_sack_blocks) {
                    blocks[count] = .{ .left = seg.start, .right = seg.end };
                    count += 1;
                }
            }
            return blocks;
        }

        // -- Internal helpers --

        /// Deliver payload directly to the receive buffer (in-order).
        fn deliverInOrder(self: *Self, payload: []const u8) usize {
            const space = self.buf_cap - self.buf_len;
            const copy_len = @min(payload.len, space);
            if (copy_len == 0) return 0;

            @memcpy(self.buf[self.buf_len .. self.buf_len + copy_len], payload[0..copy_len]);
            self.buf_len += copy_len;
            self.rcv_nxt +%= @intCast(copy_len);
            self.rcv_wnd -|= @intCast(copy_len);
            return copy_len;
        }

        /// Try to reassemble OOO segments that are now contiguous with rcv_nxt.
        fn reassemble(self: *Self) usize {
            var total: usize = 0;
            var progress = true;

            while (progress) {
                progress = false;
                for (&self.ooo) |*seg| {
                    if (!seg.active) continue;

                    // If this OOO segment now starts at or before rcv_nxt
                    if (seqLte(seg.start, self.rcv_nxt)) {
                        if (seqGt(seg.end, self.rcv_nxt)) {
                            // Partially or fully overlaps with the window edge.
                            // The bytes are already in the buffer, at
                            // buf_len onwards: insertOoo put them where they
                            // belong. Advancing rcv_nxt without buf_len
                            // acknowledged them and left them where read()
                            // never looks, and the next segment to arrive in
                            // order wrote over them.
                            const advance = @as(u32, @bitCast(@as(i32, @bitCast(seg.end -% self.rcv_nxt))));
                            self.rcv_nxt +%= advance;
                            self.buf_len += advance;
                            self.rcv_wnd -|= advance;
                            total += @intCast(advance);
                        }
                        seg.active = false;
                        progress = true;
                    }
                }
            }

            // Check if FIN is now deliverable
            if (self.fin_received and self.fin_seq == self.rcv_nxt) {
                self.rcv_nxt +%= 1;
            }

            return total;
        }

        /// Insert an out-of-order segment into the OOO tracker.
        fn insertOoo(self: *Self, start: u32, end: u32, payload: []const u8) void {
            // Store the data where it belongs, which is past what the
            // application has yet to read by however far this segment is
            // past rcv_nxt.
            const offset_from_nxt = @as(usize, @intCast(@as(u32, @bitCast(@as(i32, @bitCast(start -% self.rcv_nxt))))));
            const buf_pos = self.buf_len + offset_from_nxt;
            // No room for it: forget the segment as well as the bytes.
            // Remembering it would have reassembly acknowledge data that was
            // never stored, and the peer has to send it again either way.
            if (buf_pos + payload.len > self.buf_cap) return;
            @memcpy(self.buf[buf_pos .. buf_pos + payload.len], payload);

            // Try to merge with existing OOO segments
            for (&self.ooo) |*seg| {
                if (!seg.active) continue;
                // Check for overlap/adjacency
                if (seqLte(seg.start, end) and seqLte(start, seg.end)) {
                    // Merge: expand existing segment
                    if (seqLt(start, seg.start)) seg.start = start;
                    if (seqGt(end, seg.end)) seg.end = end;
                    return;
                }
            }

            // No merge — find an empty slot
            for (&self.ooo) |*seg| {
                if (!seg.active) {
                    seg.* = .{ .start = start, .end = end, .active = true };
                    return;
                }
            }

            // OOO table full — drop (caller will retransmit anyway)
        }

        /// How far past buf_len the bytes of out-of-order segments reach.
        /// Those bytes are addressed from buf_len, so anything that moves
        /// the buffer has to move them too.
        fn oooSpan(self: *const Self) usize {
            var span: usize = 0;
            for (&self.ooo) |*seg| {
                if (!seg.active) continue;
                if (!seqGt(seg.end, self.rcv_nxt)) continue;
                const end_off: usize = @intCast(@as(u32, @bitCast(@as(i32, @bitCast(seg.end -% self.rcv_nxt)))));
                if (end_off > span) span = end_off;
            }
            return @min(span, self.buf_cap - self.buf_len);
        }

        /// Check if a segment [start, end) overlaps with the receive window.
        fn inWindow(self: *const Self, start: u32, end: u32) bool {
            const win_end = self.rcv_nxt +% self.rcv_wnd;
            // At least part of the segment must be in [rcv_nxt, rcv_nxt+rcv_wnd)
            return seqLt(start, win_end) and seqGt(end, self.rcv_nxt -% 1);
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Receiver: in-order delivery" {
    var rx = Receiver.init(1000, 65535);
    // rcv_nxt should be 1001 (after SYN)

    const delivered = rx.onSegment(1001, "hello");
    try testing.expectEqual(@as(usize, 5), delivered);
    try testing.expectEqual(@as(u32, 1006), rx.rcv_nxt);
    try testing.expect(rx.ack_needed);

    var buf: [10]u8 = undefined;
    const n = rx.read(&buf);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualSlices(u8, "hello", buf[0..5]);
}

test "Receiver: out-of-order and reassembly" {
    var rx = Receiver.init(1000, 65535);
    // rcv_nxt = 1001

    // Receive segment 2 first (OOO)
    const d1 = rx.onSegment(1006, "world");
    try testing.expectEqual(@as(usize, 0), d1); // not delivered yet
    try testing.expect(rx.immediate_ack);

    // Now receive segment 1 (fills the gap)
    const d2 = rx.onSegment(1001, "hello");
    try testing.expectEqual(@as(usize, 5), d2);
    // After reassembly, rcv_nxt should cover both segments
    try testing.expectEqual(@as(u32, 1011), rx.rcv_nxt);
}

test "Receiver: duplicate segment ignored" {
    var rx = Receiver.init(1000, 65535);

    const d1 = rx.onSegment(1001, "hello");
    try testing.expectEqual(@as(usize, 5), d1);

    // Send same segment again
    const d2 = rx.onSegment(1001, "hello");
    try testing.expectEqual(@as(usize, 0), d2);
}

test "Receiver: partial overlap" {
    var rx = Receiver.init(1000, 65535);

    // Deliver first part
    _ = rx.onSegment(1001, "hel");
    try testing.expectEqual(@as(u32, 1004), rx.rcv_nxt);

    // Send overlapping segment: "ello" covers seq 1002-1005
    // overlap = rcv_nxt(1004) - seg_seq(1002) = 2, new = "lo" (2 bytes)
    const d = rx.onSegment(1002, "ello");
    try testing.expectEqual(@as(usize, 2), d);
    try testing.expectEqual(@as(u32, 1006), rx.rcv_nxt);
}

test "Receiver: FIN delivery" {
    var rx = Receiver.init(1000, 65535);
    _ = rx.onSegment(1001, "hi");
    try testing.expectEqual(@as(u32, 1003), rx.rcv_nxt);

    rx.onFin(1003);
    try testing.expectEqual(@as(u32, 1004), rx.rcv_nxt); // FIN consumes 1 seq
    try testing.expect(rx.fin_received);
}

test "Receiver: window management" {
    var rx = Receiver.init(1000, 1000);
    // Window = 1000

    _ = rx.onSegment(1001, &([_]u8{0x42} ** 500));
    try testing.expectEqual(@as(u32, 500), rx.rcv_wnd);

    // Read back → window should grow
    var discard: [500]u8 = undefined;
    _ = rx.read(&discard);
    try testing.expectEqual(@as(u32, 1000), rx.rcv_wnd);
}

test "Receiver: SACK blocks" {
    var rx = Receiver.init(1000, 65535);
    rx.sack_permitted = true;

    // Create OOO gap
    _ = rx.onSegment(1011, "seg2"); // OOO
    _ = rx.onSegment(1020, "seg3"); // OOO

    const blocks = rx.sackBlocks();
    // Should have 2 SACK blocks
    try testing.expect(blocks[0] != null);
    try testing.expect(blocks[1] != null);
    try testing.expect(blocks[2] == null);
}

test "ReceiverWith: embedded_minimal config" {
    const SmallRx = ReceiverWith(Config.embedded_minimal);
    var rx = SmallRx.init(5000, 2048);

    try testing.expectEqual(@as(u32, 5001), rx.rcv_nxt);
    try testing.expectEqual(@as(usize, 2048), rx.buf_cap);
    try testing.expectEqual(@as(usize, 4), rx.ooo.len);
    try testing.expect(!rx.auto_tune.enabled);

    // Deliver data within small buffer
    const delivered = rx.onSegment(5001, "hello");
    try testing.expectEqual(@as(usize, 5), delivered);

    var buf: [10]u8 = undefined;
    const n = rx.read(&buf);
    try testing.expectEqualSlices(u8, "hello", buf[0..n]);
}

test "ReceiverWith: small buffer fills correctly" {
    const TinyRx = ReceiverWith(.{ .recv_buf_size = 16, .max_ooo_segments = 2, .auto_tune_enabled = false });
    var rx = TinyRx.init(0, 16);

    // Fill buffer completely
    const d1 = rx.onSegment(1, &([_]u8{'A'} ** 16));
    try testing.expectEqual(@as(usize, 16), d1);

    // Buffer full — next segment dropped
    const d2 = rx.onSegment(17, "more");
    try testing.expectEqual(@as(usize, 0), d2);

    // Read some, then more can be delivered
    var discard: [8]u8 = undefined;
    _ = rx.read(&discard);
    try testing.expectEqual(@as(usize, 8), rx.buf_len);
}

test "Receiver: the bytes that filled a gap are the ones the application reads" {
    var rx = Receiver.init(1000, 65535);

    // The second half arrives first, so it waits for the first.
    try testing.expectEqual(@as(usize, 0), rx.onSegment(1006, "world"));
    try testing.expectEqual(@as(u32, 1001), rx.rcv_nxt);

    // The first half closes the gap, and both are now the application's.
    try testing.expectEqual(@as(usize, 5), rx.onSegment(1001, "hello"));
    try testing.expectEqual(@as(u32, 1011), rx.rcv_nxt);

    var buf: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 10), rx.read(&buf));
    try testing.expectEqualStrings("helloworld", buf[0..10]);
    try testing.expectEqual(@as(usize, 0), rx.read(&buf));
}

test "Receiver: reading does not leave the out-of-order bytes behind" {
    var rx = Receiver.init(1000, 65535);

    // Something in order, then a gap, then something past it.
    try testing.expectEqual(@as(usize, 5), rx.onSegment(1001, "first"));
    try testing.expectEqual(@as(usize, 0), rx.onSegment(1011, "third"));

    // The application takes what it can while the gap is still open, which
    // moves everything in the buffer — the bytes waiting past the gap
    // included, since where they sit is measured from what is unread.
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 5), rx.read(&buf));
    try testing.expectEqualStrings("first", buf[0..5]);

    try testing.expectEqual(@as(usize, 5), rx.onSegment(1006, "secnd"));
    try testing.expectEqual(@as(u32, 1016), rx.rcv_nxt);

    var rest: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 10), rx.read(&rest));
    try testing.expectEqualStrings("secndthird", rest[0..10]);
}

test "Receiver: a segment with nowhere to go is not remembered" {
    // A receiver with room for eight bytes, and a segment that would land
    // past the end of it. Remembering the segment without its bytes would
    // have the gap close over data that was never stored.
    var rx = ReceiverWith(.{ .recv_buf_size = 8 }).init(1000, 8);
    try testing.expectEqual(@as(usize, 0), rx.onSegment(1005, "far away"));
    try testing.expectEqual(@as(usize, 4), rx.onSegment(1001, "abcd"));
    try testing.expectEqual(@as(u32, 1005), rx.rcv_nxt); // not past the gap

    var buf: [16]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), rx.read(&buf));
    try testing.expectEqualStrings("abcd", buf[0..4]);
}
