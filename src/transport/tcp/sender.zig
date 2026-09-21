// TCP Sender: manages the send-side of a TCP connection.
//
// Responsibilities:
// - Segmentation: splits send buffer into MSS-sized segments
// - Retransmission queue: tracks unacknowledged segments for retransmit
// - RTT estimation: measures round-trip time
// - Congestion control: regulates sending rate
// - Timer management: drives retransmit/delayed-ack/keepalive
// - Nagle algorithm: coalesces small segments
//
// Sans-IO: the Sender produces "emit" actions; the caller is responsible
// for actually building and sending packets.

const std = @import("std");
const rtt_mod = @import("rtt.zig");
const congestion_mod = @import("congestion.zig");
const bbr_mod = @import("bbr.zig");
const timer_mod = @import("timer.zig");
const endpoint_mod = @import("endpoint.zig");
const options_mod = @import("options.zig");
const config_mod = @import("../../config.zig");
pub const Config = config_mod.Config;

const RttEstimator = rtt_mod.RttEstimator;
const Controller = congestion_mod.Controller;
const Bbr = bbr_mod.Bbr;
const Timer = timer_mod.Timer;

/// A segment in the retransmission queue.
pub const RetxSegment = struct {
    /// Sequence number of the first byte in this segment.
    seq: u32,
    /// Length in bytes (data + SYN/FIN each count as 1).
    len: u32,
    /// Timestamp when first sent (for RTT measurement).
    sent_at: u64,
    /// Whether this segment has been retransmitted (Karn's algorithm: skip RTT sample).
    retransmitted: bool = false,
    /// Whether this segment has been selectively acknowledged (SACK).
    sacked: bool = false,
    /// Payload offset in the send buffer (for retransmit).
    buf_offset: usize = 0,
    /// Payload length (actual data bytes, excludes SYN/FIN virtual bytes).
    data_len: usize = 0,
    /// Whether this is a SYN segment.
    is_syn: bool = false,
    /// Whether this is a FIN segment.
    is_fin: bool = false,
    /// BBR per-packet delivery state (captured at send time).
    bbr_delivered: u64 = 0,
    bbr_delivered_time: u64 = 0,
};

/// Output action from the Sender.
pub const EmitAction = union(enum) {
    /// Nothing to do.
    none,
    /// Emit a data segment starting at buf_offset with data_len bytes.
    send_data: struct {
        seq: u32,
        buf_offset: usize,
        data_len: usize,
        /// These bytes have been sent before, so they are already counted as
        /// sent and in flight. Only a first transmission moves those marks.
        retransmit: bool = false,
    },
    /// Emit a SYN segment.
    send_syn: struct {
        seq: u32,
    },
    /// Emit a FIN segment.
    send_fin: struct {
        seq: u32,
    },
    /// Connection aborted due to max retransmits.
    abort,
};

/// RACK (Recent ACKnowledgment) loss detection state (RFC 8985).
pub const RackState = struct {
    /// Send timestamp of the most recently ACKed segment.
    xmit_ts: u64 = 0,
    /// RTT of the most recently ACKed segment.
    rtt_us: u64 = 0,
    /// Reordering window (min_rtt/4 by default).
    reorder_wnd: u64 = 0,
    /// Whether RACK has been initialized (first ACK received).
    active: bool = false,

    /// Update RACK state when a segment is (cumulatively or selectively) ACKed.
    pub fn update(self: *RackState, seg_sent_at: u64, now_ms: u64) void {
        const seg_rtt = if (now_ms > seg_sent_at) now_ms - seg_sent_at else 0;
        if (!self.active or seg_sent_at > self.xmit_ts or (seg_sent_at == self.xmit_ts and seg_rtt >= self.rtt_us)) {
            self.xmit_ts = seg_sent_at;
            self.rtt_us = seg_rtt;
            self.reorder_wnd = seg_rtt / 4;
            if (self.reorder_wnd == 0 and seg_rtt > 0) self.reorder_wnd = 1;
            self.active = true;
        }
    }

    /// Check if an unacked segment should be considered lost.
    pub fn isLost(self: *const RackState, seg_sent_at: u64, now_ms: u64) bool {
        if (!self.active) return false;
        const deadline = seg_sent_at +| self.rtt_us +| self.reorder_wnd;
        return now_ms >= deadline;
    }
};

/// Default Sender (uses Config.default — backwards-compatible).
pub const Sender = SenderWith(.{});

/// Configurable TCP Sender parameterized by comptime Config.
pub fn SenderWith(comptime cfg: Config) type {
    return struct {
        const Self = @This();
        const retx_queue_size = cfg.max_retx_queue;

        // -- Sequence state --
        /// Oldest unacknowledged sequence number.
        snd_una: u32 = 0,
        /// Next sequence number to send.
        snd_nxt: u32 = 0,
        /// Initial send sequence number.
        iss: u32 = 0,

        // -- Send buffer tracking --
        /// How many bytes from send buffer have been sent but not acked.
        /// (snd_nxt - snd_una in data bytes, excluding SYN/FIN)
        flight_size: usize = 0,

        // -- Retransmission queue (fixed ring buffer) --
        retx_queue: [retx_queue_size]RetxSegment = undefined,
        retx_head: usize = 0,
        retx_tail: usize = 0,
        retx_count: usize = 0,

        // -- Modules --
        rtt: RttEstimator = .{},
        congestion: Controller = Controller.init(.reno, cfg.default_mss),
        timer: Timer = .{ .idle = .{} },

        // -- RACK loss detection --
        rack: RackState = .{},

        // -- Config --
        mss: u16 = cfg.default_mss,
        nagle_enabled: bool = cfg.nagle_enabled,

        // -- Duplicate ACK tracking --
        dup_ack_count: u8 = 0,
        last_ack_seq: u32 = 0,

        // -- Fast Recovery (NewReno RFC 6582) --
        in_fast_recovery: bool = false,
        recovery_point: u32 = 0,

        // -- State flags --
        syn_sent: bool = false,
        syn_acked: bool = false,
        fin_sent: bool = false,
        fin_acked: bool = false,

        /// Initialize sender for a new connection.
        pub fn init(iss: u32, mss: u16) Self {
            return Self{
                .snd_una = iss,
                .snd_nxt = iss,
                .iss = iss,
                .mss = mss,
                .congestion = Controller.init(.reno, mss),
            };
        }

        /// Record a SYN this side has already put on the wire so the
        /// retransmit queue owns it like any other segment. A passive open
        /// answers with SYN+ACK before poll() ever runs, and writing the ring
        /// by hand there left its tail behind its count: the next segment
        /// overwrote the SYN, and the entry the ring handed out once the data
        /// was acked had never been written at all.
        pub fn trackSyn(self: *Self, seq: u32, now_ms: u64) void {
            self.syn_sent = true;
            self.snd_una = seq;
            self.snd_nxt = seq +% 1;
            self.enqueue(.{
                .seq = seq,
                .len = 1,
                .sent_at = now_ms,
                .is_syn = true,
            });
        }

        /// The send buffer compacted by `acked_bytes`, so every segment still
        /// in the queue starts that much earlier in it. Without this a
        /// retransmission after a partial ACK resends the wrong bytes.
        pub fn shiftBufOffsets(self: *Self, acked_bytes: usize) void {
            var i: usize = 0;
            var idx = self.retx_head;
            while (i < self.retx_count) : (i += 1) {
                self.retx_queue[idx].buf_offset -|= acked_bytes;
                idx = (idx + 1) % retx_queue_size;
            }
        }

        /// Available send window (min of cwnd and rwnd minus in-flight).
        pub fn availableWindow(self: *const Self) usize {
            const cwnd = self.congestion.window();
            if (cwnd <= self.flight_size) return 0;
            return cwnd - self.flight_size;
        }

        /// How many bytes we can send right now.
        /// Implements sender-side SWS avoidance (RFC 1122 4.2.3.4):
        /// only send if window >= min(MSS, 1/2 max_window) or all data fits.
        pub fn canSend(self: *const Self, send_buf_pending: usize) usize {
            const window = self.availableWindow();
            if (window == 0) return 0;
            // SWS avoidance: don't send into a tiny window unless it's all we have
            const threshold = @min(@as(usize, self.mss), self.congestion.window() / 2);
            if (window < threshold and send_buf_pending > window) {
                return 0;
            }
            return @min(window, send_buf_pending);
        }

        /// Generate the next segment to send (if any).
        /// `send_buf_pending`: total unsent bytes in the application send buffer.
        /// `has_fin`: whether the application has requested close.
        /// Returns an EmitAction describing what to send.
        pub fn poll(self: *Self, now_ms: u64, send_buf_pending: usize, has_fin: bool) EmitAction {
            // Check timer expiry
            if (self.timer.shouldFire(now_ms)) {
                return self.handleTimerExpiry(now_ms);
            }

            // If SYN not yet sent
            if (!self.syn_sent) {
                self.syn_sent = true;
                const bbr_state = self.getBbrSendState();
                self.snd_nxt +%= 1; // SYN consumes 1 seq
                self.congestion.onSend(1);
                self.enqueue(.{
                    .seq = self.iss,
                    .len = 1,
                    .sent_at = now_ms,
                    .is_syn = true,
                    .bbr_delivered = bbr_state.delivered,
                    .bbr_delivered_time = bbr_state.delivered_time,
                });
                self.timer.setRetransmit(now_ms, self.rtt.rtoMs());
                self.rtt.startSample(now_ms, self.iss);
                return .{ .send_syn = .{ .seq = self.iss } };
            }

            // SYN must be acked before sending data
            if (!self.syn_acked) return .none;

            // Try to send data
            const available = self.canSend(send_buf_pending);
            if (available > 0) {
                const seg_len = @min(available, @as(usize, self.mss));

                // Nagle: don't send small segments if there's unacked data
                if (self.nagle_enabled and seg_len < self.mss and self.flight_size > 0) {
                    // Exception: if this is all remaining data
                    if (seg_len < send_buf_pending) {
                        return .none;
                    }
                }

                const seq = self.snd_nxt;
                const buf_offset = self.flightDataSize();

                // Capture BBR per-packet state before updating
                const bbr_state = self.getBbrSendState();

                self.snd_nxt +%= @intCast(seg_len);
                self.flight_size += seg_len;
                self.congestion.onSend(seg_len);

                self.enqueue(.{
                    .seq = seq,
                    .len = @intCast(seg_len),
                    .sent_at = now_ms,
                    .buf_offset = buf_offset,
                    .data_len = seg_len,
                    .bbr_delivered = bbr_state.delivered,
                    .bbr_delivered_time = bbr_state.delivered_time,
                });

                // Start RTT sampling if not already
                self.rtt.startSample(now_ms, seq);

                // Arm retransmit timer
                self.timer.setRetransmit(now_ms, self.rtt.rtoMs());

                return .{ .send_data = .{
                    .seq = seq,
                    .buf_offset = buf_offset,
                    .data_len = seg_len,
                } };
            }

            // FIN
            if (has_fin and !self.fin_sent and send_buf_pending == 0) {
                self.fin_sent = true;
                const seq = self.snd_nxt;
                const bbr_state = self.getBbrSendState();
                self.snd_nxt +%= 1;
                self.congestion.onSend(1);

                self.enqueue(.{
                    .seq = seq,
                    .len = 1,
                    .sent_at = now_ms,
                    .is_fin = true,
                    .bbr_delivered = bbr_state.delivered,
                    .bbr_delivered_time = bbr_state.delivered_time,
                });
                self.timer.setRetransmit(now_ms, self.rtt.rtoMs());
                return .{ .send_fin = .{ .seq = seq } };
            }

            return .none;
        }

        /// Process an incoming ACK.
        /// Returns the number of data bytes acknowledged (for buffer consumption).
        pub fn onAck(self: *Self, now_ms: u64, ack_seq: u32) usize {
            // Ignore old/duplicate ACKs
            if (!endpoint_mod.seqGt(ack_seq, self.snd_una)) {
                // Duplicate ACK
                if (ack_seq == self.last_ack_seq and self.flight_size > 0) {
                    self.dup_ack_count +|= 1;
                    if (self.dup_ack_count == 3 and !self.in_fast_recovery) {
                        // Enter Fast Recovery (RFC 6582)
                        self.in_fast_recovery = true;
                        self.recovery_point = self.snd_nxt;
                        self.congestion.onDuplicateAck();
                        self.timer.setFastRetransmit();
                    } else if (self.dup_ack_count > 3 and self.in_fast_recovery) {
                        // Each additional dup-ACK inflates cwnd by MSS
                        self.congestion.inflateCwnd();
                    }
                }
                return 0;
            }

            // New ACK — update dup-ACK tracking
            self.dup_ack_count = 0;
            self.last_ack_seq = ack_seq;

            // Update RTT
            self.rtt.onAck(now_ms, ack_seq);

            // Dequeue acknowledged segments and update RACK
            var data_acked: usize = 0;
            var last_bbr_delivered: u64 = 0;
            var last_bbr_delivered_time: u64 = 0;
            var last_rtt_ms: u64 = 0;
            while (self.retx_count > 0) {
                const seg = self.peekHead() orelse break;
                const seg_end = seg.seq +% seg.len;
                if (!endpoint_mod.seqLte(seg_end, ack_seq)) break;

                // Update RACK with this ACKed segment's send time
                if (!seg.retransmitted) {
                    self.rack.update(seg.sent_at, now_ms);
                    // Compute RTT for BBR (only from non-retransmitted segments)
                    last_rtt_ms = now_ms -| seg.sent_at;
                }

                // Track per-packet BBR state for the most recent ACKed segment
                last_bbr_delivered = seg.bbr_delivered;
                last_bbr_delivered_time = seg.bbr_delivered_time;

                // This segment is fully acked
                if (seg.is_syn) {
                    self.syn_acked = true;
                } else if (seg.is_fin) {
                    self.fin_acked = true;
                } else {
                    data_acked += seg.data_len;
                }
                self.dequeue();
            }

            // Update flight size
            if (data_acked <= self.flight_size) {
                self.flight_size -= data_acked;
            } else {
                self.flight_size = 0;
            }

            // Update snd_una
            self.snd_una = ack_seq;

            // Fast Recovery (NewReno) handling
            if (self.in_fast_recovery) {
                if (endpoint_mod.seqGte(ack_seq, self.recovery_point)) {
                    // Full ACK: exit Fast Recovery, cwnd = ssthresh
                    self.in_fast_recovery = false;
                    self.congestion.deflateCwnd();
                } else {
                    // Partial ACK (RFC 6582 §3.2): deflate by acked, add MSS, retransmit
                    self.congestion.onPartialAck(data_acked);
                    self.timer.setFastRetransmit();
                }
            } else if (data_acked > 0) {
                // Use BBR-aware ACK with per-packet delivery state and RTT
                self.congestion.onAckBbr(now_ms, data_acked, last_bbr_delivered, last_bbr_delivered_time, last_rtt_ms);
            }

            // RACK: check remaining segments for time-based loss
            self.rackDetectLosses(now_ms);

            // If everything is acked, stop the timer
            if (self.retx_count == 0) {
                self.timer.onAck();
            } else {
                // Reset timer for remaining segments
                self.timer.setRetransmit(now_ms, self.rtt.rtoMs());
            }

            return data_acked;
        }

        /// RACK: detect losses based on time rather than dup-ACK counting.
        fn rackDetectLosses(self: *Self, now_ms: u64) void {
            if (!self.rack.active) return;

            var i: usize = 0;
            var idx = self.retx_head;
            var found_loss = false;
            while (i < self.retx_count) : (i += 1) {
                const seg = &self.retx_queue[idx];
                if (!seg.sacked and !seg.retransmitted) {
                    if (self.rack.isLost(seg.sent_at, now_ms)) {
                        found_loss = true;
                        break;
                    }
                }
                idx = (idx + 1) % retx_queue_size;
            }

            if (found_loss) {
                self.congestion.onDuplicateAck();
                self.timer.setFastRetransmit();
            }
        }

        /// Handle a timer expiry. Called from poll() when timer fires.
        fn handleTimerExpiry(self: *Self, now_ms: u64) EmitAction {
            switch (self.timer) {
                .retransmit => {
                    // Retransmission timeout — exit Fast Recovery if active
                    self.rtt.onRetransmit();
                    self.congestion.onRetransmit();
                    self.dup_ack_count = 0;
                    self.in_fast_recovery = false;

                    // Check if we've exceeded max retransmits
                    const aborted = self.timer.onRetransmitTimeout(now_ms, self.rtt.rtoMs());
                    if (aborted) return .abort;

                    // Retransmit the first un-SACKed segment
                    if (self.firstUnsackedSeg()) |seg| {
                        self.markRetransmitted(seg.seq);

                        if (seg.is_syn) {
                            return .{ .send_syn = .{ .seq = seg.seq } };
                        } else if (seg.is_fin) {
                            return .{ .send_fin = .{ .seq = seg.seq } };
                        } else {
                            return .{ .send_data = .{
                                .seq = seg.seq,
                                .buf_offset = seg.buf_offset,
                                .data_len = seg.data_len,
                                .retransmit = true,
                            } };
                        }
                    }
                    return .none;
                },
                .fast_retransmit => {
                    // Retransmit the first un-SACKed segment immediately
                    if (self.firstUnsackedSeg()) |seg| {
                        self.markRetransmitted(seg.seq);
                        self.timer.setRetransmit(now_ms, self.rtt.rtoMs());

                        if (seg.is_syn) {
                            return .{ .send_syn = .{ .seq = seg.seq } };
                        } else if (seg.is_fin) {
                            return .{ .send_fin = .{ .seq = seg.seq } };
                        } else {
                            return .{ .send_data = .{
                                .seq = seg.seq,
                                .buf_offset = seg.buf_offset,
                                .data_len = seg.data_len,
                                .retransmit = true,
                            } };
                        }
                    }
                    self.timer.reset();
                    return .none;
                },
                .zero_window_probe => {
                    // Send a 1-byte probe
                    self.timer.setZeroWindowProbe(now_ms, self.rtt.rtoMs());
                    return .none; // Caller handles zero-window probe
                },
                .idle => {
                    // Keepalive (handled by caller)
                    return .none;
                },
                .delayed_ack => {
                    // Delayed ACK expired — caller should send ACK
                    self.timer.reset();
                    return .none;
                },
                .time_wait => {
                    return .none;
                },
            }
        }

        /// Set remote window (from received segment, after applying window scale).
        pub fn setRemoteWindow(self: *Self, rwnd: u32) void {
            self.congestion.setRemoteWindow(@as(usize, rwnd));
        }

        /// Process incoming SACK blocks from peer.
        /// Marks segments in retx queue as SACKed so they are skipped on retransmit.
        /// Also updates RACK state with newly SACKed segments.
        pub fn onSackBlocks(self: *Self, now_ms: u64, blocks: []const options_mod.SackBlock) void {
            for (blocks) |block| {
                var i: usize = 0;
                var idx = self.retx_head;
                while (i < self.retx_count) : (i += 1) {
                    const seg = &self.retx_queue[idx];
                    if (!seg.sacked and !seg.is_syn and !seg.is_fin) {
                        const seg_end = seg.seq +% seg.len;
                        if (endpoint_mod.seqLte(block.left, seg.seq) and endpoint_mod.seqLte(seg_end, block.right)) {
                            seg.sacked = true;
                            // RACK: update with this SACKed segment
                            if (!seg.retransmitted) {
                                self.rack.update(seg.sent_at, now_ms);
                            }
                        }
                    }
                    idx = (idx + 1) % retx_queue_size;
                }
            }
            // After processing SACK blocks, check for RACK losses
            self.rackDetectLosses(now_ms);
        }

        /// Find the first un-SACKed segment for retransmission (skips SACKed).
        fn firstUnsackedSeg(self: *const Self) ?RetxSegment {
            var i: usize = 0;
            var idx = self.retx_head;
            while (i < self.retx_count) : (i += 1) {
                const seg = self.retx_queue[idx];
                if (!seg.sacked) return seg;
                idx = (idx + 1) % retx_queue_size;
            }
            return null;
        }

        /// Set MSS (from options negotiation).
        pub fn setMss(self: *Self, mss: u16) void {
            self.mss = mss;
            self.congestion.setMss(mss);
        }

        /// Get the next poll deadline (for event loop).
        pub fn nextPollAt(self: *const Self) ?u64 {
            return self.timer.nextPollAt();
        }

        // -- Internal ring buffer operations --

        fn enqueue(self: *Self, seg: RetxSegment) void {
            if (self.retx_count >= retx_queue_size) {
                // Queue full — drop oldest (shouldn't happen in practice)
                self.dequeue();
            }
            self.retx_queue[self.retx_tail] = seg;
            self.retx_tail = (self.retx_tail + 1) % retx_queue_size;
            self.retx_count += 1;
        }

        fn dequeue(self: *Self) void {
            if (self.retx_count == 0) return;
            self.retx_head = (self.retx_head + 1) % retx_queue_size;
            self.retx_count -= 1;
        }

        fn peekHead(self: *const Self) ?RetxSegment {
            if (self.retx_count == 0) return null;
            return self.retx_queue[self.retx_head];
        }

        fn updateHead(self: *Self, seg: RetxSegment) void {
            if (self.retx_count > 0) {
                self.retx_queue[self.retx_head] = seg;
            }
        }

        fn markRetransmitted(self: *Self, seq: u32) void {
            var i: usize = 0;
            var idx = self.retx_head;
            while (i < self.retx_count) : (i += 1) {
                if (self.retx_queue[idx].seq == seq) {
                    self.retx_queue[idx].retransmitted = true;
                    return;
                }
                idx = (idx + 1) % retx_queue_size;
            }
        }

        /// Calculate total data bytes in flight (exclude SYN/FIN virtual bytes).
        fn flightDataSize(self: *const Self) usize {
            var total: usize = 0;
            var i: usize = 0;
            var idx = self.retx_head;
            while (i < self.retx_count) : (i += 1) {
                total += self.retx_queue[idx].data_len;
                idx = (idx + 1) % retx_queue_size;
            }
            return total;
        }

        /// Get BBR per-packet send state snapshot from the congestion controller.
        fn getBbrSendState(self: *const Self) bbr_mod.SendState {
            switch (self.congestion) {
                .bbr => |*b| return b.getSendState(),
                else => return .{},
            }
        }

        /// Feed an RTT sample to BBR (called externally when timestamps provide a sample).
        pub fn updateBbrRtt(self: *Self, now_ms: u64, rtt_ms: u64) void {
            switch (self.congestion) {
                .bbr => |*b| b.updateRtProp(rtt_ms, now_ms),
                else => {},
            }
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Sender: SYN on first poll" {
    var sender = Sender.init(1000, 1460);

    const action = sender.poll(0, 0, false);
    switch (action) {
        .send_syn => |s| {
            try testing.expectEqual(@as(u32, 1000), s.seq);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(sender.syn_sent);
    try testing.expectEqual(@as(u32, 1001), sender.snd_nxt);
    try testing.expectEqual(@as(usize, 1), sender.retx_count);
}

test "Sender: SYN ACK advances state" {
    var sender = Sender.init(1000, 1460);
    _ = sender.poll(0, 0, false); // send SYN

    // ACK the SYN (ack_seq = ISS+1 = 1001)
    const acked = sender.onAck(50, 1001);
    try testing.expectEqual(@as(usize, 0), acked); // SYN is not data
    try testing.expect(sender.syn_acked);
    try testing.expectEqual(@as(usize, 0), sender.retx_count);
}

test "Sender: data segmentation" {
    var sender = Sender.init(1000, 100); // MSS=100 for easy testing
    _ = sender.poll(0, 0, false); // SYN
    _ = sender.onAck(50, 1001); // ACK SYN

    // 250 bytes pending → should send 100 bytes (MSS)
    const action1 = sender.poll(100, 250, false);
    switch (action1) {
        .send_data => |d| {
            try testing.expectEqual(@as(u32, 1001), d.seq);
            try testing.expectEqual(@as(usize, 100), d.data_len);
        },
        else => return error.TestUnexpectedResult,
    }

    // Poll again → another 100 bytes
    const action2 = sender.poll(100, 150, false);
    switch (action2) {
        .send_data => |d| {
            try testing.expectEqual(@as(u32, 1101), d.seq);
            try testing.expectEqual(@as(usize, 100), d.data_len);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "Sender: retransmit on timeout" {
    var sender = Sender.init(1000, 1460);
    _ = sender.poll(0, 0, false); // SYN at t=0

    // Don't ACK; poll after RTO (initial = 1000ms)
    const action = sender.poll(1000, 0, false);
    switch (action) {
        .send_syn => |s| {
            try testing.expectEqual(@as(u32, 1000), s.seq); // retransmit same SYN
        },
        else => return error.TestUnexpectedResult,
    }
}

test "Sender: FIN after all data acked" {
    var sender = Sender.init(1000, 100);
    sender.nagle_enabled = false;
    _ = sender.poll(0, 0, false); // SYN
    _ = sender.onAck(50, 1001); // ACK SYN

    // Send 50 bytes
    const action1 = sender.poll(100, 50, false);
    switch (action1) {
        .send_data => |d| {
            try testing.expectEqual(@as(usize, 50), d.data_len);
        },
        else => return error.TestUnexpectedResult,
    }

    // ACK the data
    _ = sender.onAck(150, 1051);

    // Now request close with no pending data
    const action2 = sender.poll(200, 0, true);
    switch (action2) {
        .send_fin => |f| {
            try testing.expectEqual(@as(u32, 1051), f.seq);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(sender.fin_sent);
}

test "Sender: abort after max retransmits" {
    var sender = Sender.init(1000, 1460);
    _ = sender.poll(0, 0, false); // SYN

    // Simulate repeated timeouts without ACK
    var t: u64 = 1000;
    var aborted = false;
    var i: u8 = 0;
    while (i < 20) : (i += 1) {
        const action = sender.poll(t, 0, false);
        switch (action) {
            .abort => {
                aborted = true;
                break;
            },
            else => {},
        }
        t += sender.rtt.rtoMs();
    }
    try testing.expect(aborted);
}

test "Sender: duplicate ACK triggers fast retransmit" {
    var sender = Sender.init(1000, 100);
    sender.nagle_enabled = false;
    _ = sender.poll(0, 0, false); // SYN
    _ = sender.onAck(50, 1001); // ACK SYN

    // Send 3 segments
    _ = sender.poll(100, 300, false); // seg 1: seq 1001, 100 bytes
    _ = sender.poll(100, 200, false); // seg 2: seq 1101, 100 bytes
    _ = sender.poll(100, 100, false); // seg 3: seq 1201, 100 bytes

    // 3 duplicate ACKs for seq 1001
    _ = sender.onAck(200, 1001);
    _ = sender.onAck(200, 1001);
    _ = sender.onAck(200, 1001);

    // This should trigger fast retransmit on next poll
    const action = sender.poll(200, 0, false);
    switch (action) {
        .send_data => |d| {
            try testing.expectEqual(@as(u32, 1001), d.seq); // retransmit first segment
        },
        else => return error.TestUnexpectedResult,
    }
}

test "RACK: detects loss by time" {
    var sender = Sender.init(1000, 100);
    sender.nagle_enabled = false;
    _ = sender.poll(0, 0, false); // SYN
    _ = sender.onAck(50, 1001); // ACK SYN

    // Send 3 segments at different times
    _ = sender.poll(100, 300, false); // seg 1: seq 1001, sent at t=100
    _ = sender.poll(110, 200, false); // seg 2: seq 1101, sent at t=110
    _ = sender.poll(120, 100, false); // seg 3: seq 1201, sent at t=120

    // Seg 2 and 3 are ACKed (cumulative ACK skipping seg 1)
    // Simulate: peer received seg 2 and 3, sends cumulative ACK for seg 1 only
    // but with SACK for seg 2+3
    var blocks = [_]options_mod.SackBlock{
        .{ .left = 1101, .right = 1301 },
    };
    sender.onSackBlocks(220, &blocks);

    // RACK picks the most recently sent SACKed segment: seg 3 at t=120
    // RTT for seg 3 = 220 - 120 = 100ms, reorder_wnd = 100/4 = 25ms
    try testing.expect(sender.rack.active);
    try testing.expectEqual(@as(u64, 120), sender.rack.xmit_ts);
    try testing.expectEqual(@as(u64, 100), sender.rack.rtt_us);
    try testing.expectEqual(@as(u64, 25), sender.rack.reorder_wnd);

    // Seg 1 (sent at t=100) is lost when: now >= 100 + 100 + 25 = 225
    try testing.expect(sender.rack.isLost(100, 226));
    try testing.expect(!sender.rack.isLost(100, 224));
}

test "RACK: update on cumulative ACK" {
    var sender = Sender.init(1000, 100);
    sender.nagle_enabled = false;
    _ = sender.poll(0, 0, false); // SYN
    _ = sender.onAck(50, 1001); // ACK SYN

    // Send 2 segments
    _ = sender.poll(100, 200, false); // seg 1: seq 1001, sent at t=100
    _ = sender.poll(120, 100, false); // seg 2: seq 1101, sent at t=120

    // ACK seg 1 at t=200 (RTT = 100ms)
    _ = sender.onAck(200, 1101);

    try testing.expect(sender.rack.active);
    try testing.expectEqual(@as(u64, 100), sender.rack.xmit_ts);
    try testing.expectEqual(@as(u64, 100), sender.rack.rtt_us);
    try testing.expectEqual(@as(u64, 25), sender.rack.reorder_wnd);
}

test "NewReno: enters fast recovery on 3rd dup-ACK" {
    var sender = Sender.init(1000, 100);
    sender.nagle_enabled = false;
    _ = sender.poll(0, 0, false); // SYN
    _ = sender.onAck(50, 1001); // ACK SYN

    // Send 4 segments
    _ = sender.poll(100, 400, false); // seq 1001
    _ = sender.poll(100, 300, false); // seq 1101
    _ = sender.poll(100, 200, false); // seq 1201
    _ = sender.poll(100, 100, false); // seq 1301

    // 3 dup-ACKs at 1001
    _ = sender.onAck(200, 1001);
    try testing.expect(!sender.in_fast_recovery);
    _ = sender.onAck(200, 1001);
    try testing.expect(!sender.in_fast_recovery);
    _ = sender.onAck(200, 1001);
    try testing.expect(sender.in_fast_recovery);
    try testing.expectEqual(@as(u32, 1401), sender.recovery_point);
}

test "NewReno: cwnd inflation on additional dup-ACKs" {
    var sender = Sender.init(1000, 100);
    sender.nagle_enabled = false;
    _ = sender.poll(0, 0, false); // SYN
    _ = sender.onAck(50, 1001); // ACK SYN

    _ = sender.poll(100, 400, false);
    _ = sender.poll(100, 300, false);
    _ = sender.poll(100, 200, false);
    _ = sender.poll(100, 100, false);

    // Enter fast recovery
    _ = sender.onAck(200, 1001);
    _ = sender.onAck(200, 1001);
    _ = sender.onAck(200, 1001);

    const cwnd_after_enter = sender.congestion.window();

    // 4th dup-ACK should inflate cwnd
    _ = sender.onAck(200, 1001);
    try testing.expect(sender.congestion.window() > cwnd_after_enter);
}

test "NewReno: full ACK exits fast recovery" {
    var sender = Sender.init(1000, 100);
    sender.nagle_enabled = false;
    _ = sender.poll(0, 0, false);
    _ = sender.onAck(50, 1001);

    _ = sender.poll(100, 300, false); // seq 1001
    _ = sender.poll(100, 200, false); // seq 1101
    _ = sender.poll(100, 100, false); // seq 1201

    // Enter fast recovery (recovery_point = 1301)
    _ = sender.onAck(200, 1001);
    _ = sender.onAck(200, 1001);
    _ = sender.onAck(200, 1001);
    try testing.expect(sender.in_fast_recovery);

    // Full ACK (>= recovery_point)
    _ = sender.onAck(300, 1301);
    try testing.expect(!sender.in_fast_recovery);
}

test "NewReno: partial ACK stays in recovery" {
    var sender = Sender.init(1000, 100);
    sender.nagle_enabled = false;
    _ = sender.poll(0, 0, false);
    _ = sender.onAck(50, 1001);

    _ = sender.poll(100, 300, false); // seq 1001
    _ = sender.poll(100, 200, false); // seq 1101
    _ = sender.poll(100, 100, false); // seq 1201

    // Enter fast recovery (recovery_point = 1301)
    _ = sender.onAck(200, 1001);
    _ = sender.onAck(200, 1001);
    _ = sender.onAck(200, 1001);
    try testing.expect(sender.in_fast_recovery);

    // Partial ACK (advances snd_una but < recovery_point)
    _ = sender.onAck(300, 1101);
    try testing.expect(sender.in_fast_recovery);
    try testing.expectEqual(@as(u32, 1101), sender.snd_una);
}

test "NewReno: RTO exits fast recovery" {
    var sender = Sender.init(1000, 100);
    sender.nagle_enabled = false;
    _ = sender.poll(0, 0, false);
    _ = sender.onAck(50, 1001);

    _ = sender.poll(100, 200, false);
    _ = sender.poll(100, 100, false);

    // Enter fast recovery
    _ = sender.onAck(200, 1001);
    _ = sender.onAck(200, 1001);
    _ = sender.onAck(200, 1001);
    try testing.expect(sender.in_fast_recovery);

    // Fire fast retransmit first
    _ = sender.poll(200, 0, false);

    // Then simulate RTO
    const action = sender.poll(1500, 0, false);
    _ = action;
    try testing.expect(!sender.in_fast_recovery);
}
