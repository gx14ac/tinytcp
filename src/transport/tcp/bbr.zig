// BBRv1 Congestion Control (draft-cardwell-iccrg-bbr-congestion-control).
//
// Model-based congestion control that estimates:
// - BtlBw: bottleneck bandwidth (max delivery rate over a window)
// - RTprop: propagation delay (min RTT over a window)
//
// States: Startup → Drain → ProbeBW (steady-state) → ProbeRTT (periodic)
//
// cwnd = BtlBw * RTprop * cwnd_gain
// pacing_rate = BtlBw * pacing_gain
//
// Per-packet delivery rate tracking: each sent packet records a snapshot of
// (delivered, delivered_time). On ACK, the sender passes this snapshot back
// via AckSample so BBR can compute the delivery rate for that specific packet.

const std = @import("std");

/// BBR state machine phases.
pub const State = enum {
    startup,
    drain,
    probe_bw,
    probe_rtt,
};

/// Per-packet state captured at send time, stored in RetxSegment.
pub const SendState = struct {
    delivered: u64 = 0,
    delivered_time: u64 = 0,
};

/// Passed to onAck so BBR can compute per-packet delivery rate.
pub const AckSample = struct {
    bytes: usize,
    rtt_ms: u64,
    send_state: SendState,
};

/// Number of rounds in the BtlBw windowed-max filter.
const btlbw_filter_len: usize = 10;

/// RTprop expiration: 10 seconds (probe_rtt triggered after this).
const rtprop_expire_ms: u64 = 10_000;

/// ProbeRTT duration: 200ms with inflight capped to 4 packets.
const probe_rtt_duration_ms: u64 = 200;

/// Minimum cwnd during ProbeRTT (4 packets).
const min_probe_rtt_cwnd_packets: usize = 4;

/// Startup pacing gain (2/ln(2) ≈ 2.89).
const startup_pacing_gain: u64 = 289; // /100
/// Startup cwnd gain.
const startup_cwnd_gain: u64 = 200; // /100

/// Drain pacing gain (1/startup ≈ 0.35).
const drain_pacing_gain: u64 = 35; // /100

/// ProbeBW pacing gains cycle (8 phases).
const probe_bw_gains = [8]u64{ 125, 75, 100, 100, 100, 100, 100, 100 }; // /100

/// Steady-state cwnd gain.
const probe_bw_cwnd_gain: u64 = 200; // /100

/// BBRv1 congestion controller.
pub const Bbr = struct {
    // -- Estimated model parameters --
    btl_bw: u64 = 0,
    btl_bw_filter: [btlbw_filter_len]u64 = .{0} ** btlbw_filter_len,
    btl_bw_filter_idx: usize = 0,

    rt_prop: u64 = std.math.maxInt(u64),
    rt_prop_stamp: u64 = 0,

    // -- State machine --
    state: State = .startup,
    round_count: u64 = 0,
    next_round_delivered: u64 = 0,
    round_started: bool = false,

    // -- ProbeBW state --
    probe_bw_cycle_idx: u3 = 0,
    probe_bw_cycle_stamp: u64 = 0,

    // -- ProbeRTT state --
    probe_rtt_done_stamp: u64 = 0,
    probe_rtt_round_done: bool = false,

    // -- Delivery accounting (connection-level counters) --
    delivered: u64 = 0,
    delivered_time: u64 = 0,

    // -- Startup exit detection --
    full_bw_count: u8 = 0,
    full_bw: u64 = 0,

    // -- Output --
    cwnd: usize = 0,
    pacing_rate: u64 = 0,

    // -- Config --
    mss: usize = 1460,
    min_cwnd: usize = 1460,
    rwnd: usize = 64 * 1024,

    // -- Inflight tracking --
    inflight: usize = 0,

    pub fn init(mss: u16) Bbr {
        const mss_usize = @as(usize, mss);
        const initial_cwnd = mss_usize * 10;
        return Bbr{
            .mss = mss_usize,
            .min_cwnd = mss_usize,
            .cwnd = initial_cwnd,
            .pacing_rate = 0,
        };
    }

    /// Effective send window.
    pub fn window(self: *const Bbr) usize {
        return @min(self.cwnd, self.rwnd);
    }

    /// Capture per-packet send state. Caller stores this in RetxSegment.
    pub fn getSendState(self: *const Bbr) SendState {
        return .{
            .delivered = self.delivered,
            .delivered_time = self.delivered_time,
        };
    }

    /// Record that bytes were sent (updates inflight).
    pub fn onSend(self: *Bbr, bytes: usize) void {
        self.inflight += bytes;
    }

    /// Called when bytes are acknowledged with per-packet delivery info.
    pub fn onAckDetailed(self: *Bbr, now_ms: u64, sample: AckSample) void {
        self.delivered += sample.bytes;
        self.delivered_time = now_ms;

        if (self.inflight >= sample.bytes) {
            self.inflight -= sample.bytes;
        } else {
            self.inflight = 0;
        }

        // Update round tracking first (delivery rate filter depends on round_started)
        self.updateRound();

        // Compute delivery rate from per-packet state
        self.updateDeliveryRate(now_ms, sample);

        // Update RTprop from actual RTT
        self.updateRtProp(sample.rtt_ms, now_ms);

        // State machine
        switch (self.state) {
            .startup => self.updateStartup(),
            .drain => self.updateDrain(now_ms),
            .probe_bw => self.updateProbeBw(now_ms),
            .probe_rtt => self.updateProbeRtt(now_ms),
        }

        // Recompute output
        self.computePacingRate();
        self.computeCwnd(sample.bytes);
    }

    /// Approximate fallback for Controller.onAckWithTime; prefer onAckBbr from Sender
    /// which passes real per-packet delivery state.
    pub fn onAck(self: *Bbr, now_ms: u64, acked_bytes: usize) void {
        self.onAckDetailed(now_ms, .{
            .bytes = acked_bytes,
            .rtt_ms = 0,
            .send_state = .{
                .delivered = if (self.delivered >= acked_bytes) self.delivered - acked_bytes else 0,
                .delivered_time = if (now_ms > 0) now_ms - 1 else 0,
            },
        });
    }

    /// Called on retransmission timeout.
    pub fn onRetransmit(self: *Bbr) void {
        self.inflight = 0;
        self.cwnd = self.min_cwnd;
    }

    /// Called on duplicate ACK (BBR is not loss-based, no-op).
    pub fn onDuplicateAck(_: *Bbr) void {}

    /// Called on ECN CE: reduce BtlBw estimate by 10%.
    pub fn onEcnCe(self: *Bbr) void {
        self.btl_bw = self.btl_bw * 9 / 10;
        // Also reduce the current filter slot
        self.btl_bw_filter[self.btl_bw_filter_idx] = self.btl_bw;
    }

    /// Set remote window.
    pub fn setRemoteWindow(self: *Bbr, rwnd: usize) void {
        self.rwnd = @max(rwnd, self.min_cwnd);
    }

    /// Set MSS.
    pub fn setMss(self: *Bbr, mss: u16) void {
        self.mss = @as(usize, mss);
        self.min_cwnd = @as(usize, mss);
    }

    /// Inflate cwnd (no-op for BBR, compatibility with NewReno path).
    pub fn inflateCwnd(_: *Bbr) void {}

    /// Deflate cwnd (no-op for BBR, compatibility with NewReno path).
    pub fn deflateCwnd(_: *Bbr) void {}

    /// Partial ACK (no-op for BBR, compatibility with NewReno path).
    pub fn onPartialAck(_: *Bbr, _: usize) void {}

    /// Get current pacing rate (bytes per millisecond).
    pub fn getPacingRate(self: *const Bbr) u64 {
        return self.pacing_rate;
    }

    // -- Internal: delivery rate estimation --

    fn updateDeliveryRate(self: *Bbr, now_ms: u64, sample: AckSample) void {
        // Per-packet delivery rate: (now_delivered - pkt.prior_delivered) / (now_time - pkt.prior_time)
        const delivered_delta = self.delivered -| sample.send_state.delivered;
        const time_delta = if (now_ms > sample.send_state.delivered_time)
            now_ms - sample.send_state.delivered_time
        else
            1;

        const rate = delivered_delta / time_delta;

        // Update BtlBw windowed-max filter (one slot per round)
        if (self.round_started) {
            self.btl_bw_filter_idx = (self.btl_bw_filter_idx + 1) % btlbw_filter_len;
            self.btl_bw_filter[self.btl_bw_filter_idx] = rate;
        } else {
            // Same round: keep max in current slot
            self.btl_bw_filter[self.btl_bw_filter_idx] = @max(self.btl_bw_filter[self.btl_bw_filter_idx], rate);
        }
        self.btl_bw = self.maxBtlBw();
    }

    fn maxBtlBw(self: *const Bbr) u64 {
        var max: u64 = 0;
        for (self.btl_bw_filter) |v| {
            if (v > max) max = v;
        }
        return max;
    }

    pub fn updateRtProp(self: *Bbr, rtt_ms: u64, now_ms: u64) void {
        if (rtt_ms > 0 and rtt_ms < self.rt_prop) {
            self.rt_prop = rtt_ms;
            self.rt_prop_stamp = now_ms;
        }

        // Check RTprop expiration → enter ProbeRTT
        if (now_ms -| self.rt_prop_stamp > rtprop_expire_ms) {
            if (self.state != .probe_rtt) {
                self.state = .probe_rtt;
                self.probe_rtt_done_stamp = 0;
                self.probe_rtt_round_done = false;
            }
        }
    }

    fn updateRound(self: *Bbr) void {
        if (self.delivered >= self.next_round_delivered) {
            self.round_started = true;
            self.round_count += 1;
            self.next_round_delivered = self.delivered + self.cwnd;
        } else {
            self.round_started = false;
        }
    }

    // -- State machine updates --

    fn updateStartup(self: *Bbr) void {
        if (!self.round_started) return;

        if (self.btl_bw > 0) {
            if (self.btl_bw >= self.full_bw * 5 / 4) {
                self.full_bw = self.btl_bw;
                self.full_bw_count = 0;
            } else {
                self.full_bw_count += 1;
            }
        }

        if (self.full_bw_count >= 3) {
            self.state = .drain;
        }
    }

    fn updateDrain(self: *Bbr, now_ms: u64) void {
        const bdp = self.computeBdp();
        if (self.inflight <= bdp) {
            self.state = .probe_bw;
            self.probe_bw_cycle_idx = 0;
            self.probe_bw_cycle_stamp = now_ms;
        }
    }

    fn updateProbeBw(self: *Bbr, now_ms: u64) void {
        const cycle_duration = if (self.rt_prop < std.math.maxInt(u64)) self.rt_prop else 100;
        if (now_ms -| self.probe_bw_cycle_stamp >= cycle_duration) {
            self.probe_bw_cycle_idx = @intCast((@as(u4, self.probe_bw_cycle_idx) + 1) % 8);
            self.probe_bw_cycle_stamp = now_ms;
        }
    }

    fn updateProbeRtt(self: *Bbr, now_ms: u64) void {
        const probe_cwnd = min_probe_rtt_cwnd_packets * self.mss;
        if (self.cwnd > probe_cwnd) {
            self.cwnd = probe_cwnd;
        }

        if (self.probe_rtt_done_stamp == 0) {
            if (self.inflight <= probe_cwnd) {
                self.probe_rtt_done_stamp = now_ms + probe_rtt_duration_ms;
                self.probe_rtt_round_done = false;
            }
        } else {
            if (self.round_started) {
                self.probe_rtt_round_done = true;
            }
            if (self.probe_rtt_round_done and now_ms >= self.probe_rtt_done_stamp) {
                self.rt_prop_stamp = now_ms;
                if (self.full_bw_count >= 3) {
                    self.state = .probe_bw;
                    self.probe_bw_cycle_idx = 0;
                    self.probe_bw_cycle_stamp = now_ms;
                } else {
                    self.state = .startup;
                }
            }
        }
    }

    // -- Pacing and cwnd computation --

    fn computePacingRate(self: *Bbr) void {
        const gain = self.pacingGain();
        const raw = self.btl_bw *| gain;
        self.pacing_rate = @min(raw / 100, std.math.maxInt(u64) / 2);
    }

    fn computeCwnd(self: *Bbr, acked_bytes: usize) void {
        const bdp = self.computeBdp();
        const gain = self.cwndGain();

        const target = @max(bdp *| gain / 100, self.min_cwnd);

        if (self.state == .probe_rtt) {
            self.cwnd = @min(self.cwnd, min_probe_rtt_cwnd_packets * self.mss);
            return;
        }

        if (self.cwnd < target) {
            self.cwnd += acked_bytes;
            self.cwnd = @min(self.cwnd, target);
        }
        self.cwnd = @max(self.cwnd, self.min_cwnd);
    }

    fn computeBdp(self: *const Bbr) usize {
        const rt = if (self.rt_prop < std.math.maxInt(u64)) self.rt_prop else 100;
        const bdp = self.btl_bw *| rt;
        return @intCast(@min(bdp, std.math.maxInt(usize)));
    }

    fn pacingGain(self: *const Bbr) u64 {
        return switch (self.state) {
            .startup => startup_pacing_gain,
            .drain => drain_pacing_gain,
            .probe_bw => probe_bw_gains[self.probe_bw_cycle_idx],
            .probe_rtt => 100,
        };
    }

    fn cwndGain(self: *const Bbr) u64 {
        return switch (self.state) {
            .startup => startup_cwnd_gain,
            .drain => startup_cwnd_gain,
            .probe_bw => probe_bw_cwnd_gain,
            .probe_rtt => 100,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "BBR: init starts in Startup" {
    const bbr = Bbr.init(1460);
    try testing.expectEqual(State.startup, bbr.state);
    try testing.expectEqual(@as(usize, 14600), bbr.cwnd);
}

test "BBR: window respects rwnd" {
    var bbr = Bbr.init(1460);
    bbr.rwnd = 5000;
    try testing.expectEqual(@as(usize, 5000), bbr.window());
}

test "BBR: getSendState captures current delivered" {
    var bbr = Bbr.init(1460);
    bbr.delivered = 5000;
    bbr.delivered_time = 100;

    const ss = bbr.getSendState();
    try testing.expectEqual(@as(u64, 5000), ss.delivered);
    try testing.expectEqual(@as(u64, 100), ss.delivered_time);
}

test "BBR: onAckDetailed computes delivery rate" {
    var bbr = Bbr.init(1460);
    bbr.delivered = 0;
    bbr.delivered_time = 0;
    bbr.inflight = 1460;

    // Packet was sent when delivered=0, delivered_time=0
    // ACK arrives at now=100ms, 1460 bytes
    bbr.onAckDetailed(100, .{
        .bytes = 1460,
        .rtt_ms = 100,
        .send_state = .{ .delivered = 0, .delivered_time = 0 },
    });

    // delivery_rate = 1460 / 100 = 14 bytes/ms
    try testing.expectEqual(@as(u64, 1460), bbr.delivered);
    try testing.expect(bbr.btl_bw >= 14);
}

test "BBR: RTprop updated from rtt_ms" {
    var bbr = Bbr.init(1460);
    bbr.inflight = 1460;

    bbr.onAckDetailed(100, .{
        .bytes = 1460,
        .rtt_ms = 50,
        .send_state = .{ .delivered = 0, .delivered_time = 0 },
    });

    try testing.expectEqual(@as(u64, 50), bbr.rt_prop);
}

test "BBR: startup exits after bandwidth plateau" {
    var bbr = Bbr.init(1460);

    bbr.btl_bw = 100;
    bbr.full_bw = 100;
    bbr.full_bw_count = 0;

    bbr.round_started = true;
    bbr.updateStartup();
    try testing.expectEqual(@as(u8, 1), bbr.full_bw_count);

    bbr.round_started = true;
    bbr.updateStartup();
    try testing.expectEqual(@as(u8, 2), bbr.full_bw_count);

    bbr.round_started = true;
    bbr.updateStartup();
    try testing.expectEqual(State.drain, bbr.state);
}

test "BBR: drain transitions to ProbeBW when inflight <= BDP" {
    var bbr = Bbr.init(1460);
    bbr.state = .drain;
    bbr.btl_bw = 10;
    bbr.rt_prop = 50;
    // BDP = 10 * 50 = 500
    bbr.inflight = 400;

    bbr.updateDrain(1000);
    try testing.expectEqual(State.probe_bw, bbr.state);
    try testing.expectEqual(@as(u64, 1000), bbr.probe_bw_cycle_stamp);
}

test "BBR: probe_bw cycles through gains" {
    var bbr = Bbr.init(1460);
    bbr.state = .probe_bw;
    bbr.rt_prop = 100;
    bbr.probe_bw_cycle_stamp = 0;
    bbr.probe_bw_cycle_idx = 0;

    bbr.updateProbeBw(150);
    try testing.expectEqual(@as(u3, 1), bbr.probe_bw_cycle_idx);
}

test "BBR: retransmit resets to min cwnd" {
    var bbr = Bbr.init(1460);
    bbr.cwnd = 50000;
    bbr.inflight = 30000;

    bbr.onRetransmit();
    try testing.expectEqual(@as(usize, 1460), bbr.cwnd);
    try testing.expectEqual(@as(usize, 0), bbr.inflight);
}

test "BBR: probe_rtt caps cwnd" {
    var bbr = Bbr.init(1460);
    bbr.state = .probe_rtt;
    bbr.cwnd = 50000;
    bbr.inflight = 1000;
    bbr.full_bw_count = 3;
    bbr.probe_rtt_done_stamp = 0;

    bbr.updateProbeRtt(1000);
    try testing.expect(bbr.cwnd <= 4 * 1460);
}

test "BBR: onSend tracks inflight" {
    var bbr = Bbr.init(1460);
    bbr.onSend(1460);
    try testing.expectEqual(@as(usize, 1460), bbr.inflight);
    bbr.onSend(1460);
    try testing.expectEqual(@as(usize, 2920), bbr.inflight);
}

test "BBR: window never below min_cwnd" {
    var bbr = Bbr.init(1460);
    bbr.onRetransmit();
    try testing.expect(bbr.window() >= 1460);
}

test "BBR: onEcnCe reduces btl_bw by 10%" {
    var bbr = Bbr.init(1460);
    bbr.btl_bw = 100;
    bbr.btl_bw_filter[0] = 100;
    bbr.btl_bw_filter_idx = 0;

    bbr.onEcnCe();
    try testing.expectEqual(@as(u64, 90), bbr.btl_bw);
}

test "BBR: BtlBw filter advances per round" {
    var bbr = Bbr.init(1460);
    bbr.inflight = 14600;

    // First ACK starts round 1 (delivered=1460 >= next_round_delivered=0)
    // This advances filter_idx from 0 to 1.
    bbr.onAckDetailed(100, .{
        .bytes = 1460,
        .rtt_ms = 50,
        .send_state = .{ .delivered = 0, .delivered_time = 0 },
    });
    // next_round_delivered = 1460 + cwnd(14600) = 16060
    try testing.expectEqual(@as(usize, 1), bbr.btl_bw_filter_idx);

    // Second ACK: delivered=2920 < 16060, same round → no filter advance
    bbr.onAckDetailed(110, .{
        .bytes = 1460,
        .rtt_ms = 50,
        .send_state = .{ .delivered = 1460, .delivered_time = 100 },
    });
    try testing.expectEqual(@as(usize, 1), bbr.btl_bw_filter_idx);

    // Third ACK that pushes delivered past next_round_delivered → new round
    bbr.delivered = 16000;
    bbr.inflight = 14600;
    bbr.onAckDetailed(200, .{
        .bytes = 1460,
        .rtt_ms = 50,
        .send_state = .{ .delivered = 14000, .delivered_time = 100 },
    });
    // Should have advanced to idx 2
    try testing.expectEqual(@as(usize, 2), bbr.btl_bw_filter_idx);
}

test "BBR: next_round_delivered uses u64 (no overflow)" {
    var bbr = Bbr.init(1460);
    bbr.delivered = 5_000_000_000; // > u32 max
    bbr.next_round_delivered = 5_000_000_000;
    bbr.cwnd = 14600;

    bbr.updateRound();
    try testing.expect(bbr.round_started);
    try testing.expectEqual(@as(u64, 5_000_000_000 + 14600), bbr.next_round_delivered);
}
