// CUBIC Congestion Control (RFC 8312).
//
// CUBIC is the default congestion control algorithm in Linux.
// It uses a cubic function of time since the last congestion event
// to compute the congestion window:
//
//   W(t) = C * (t - K)^3 + W_max
//
// where:
//   C = 0.4 (scaling constant)
//   K = cubic_root(W_max * beta / C)
//   beta = 0.7 (multiplicative decrease factor)
//   W_max = window size just before last reduction
//   t = time since last congestion event
//
// Also implements TCP-friendly mode (Reno-equivalent window as lower bound).

const std = @import("std");

/// CUBIC parameters.
const C: f64 = 0.4;
const BETA: f64 = 0.7;
const BETA_SCALE: u64 = 7; // BETA = 7/10

/// CUBIC congestion controller state.
pub const Cubic = struct {
    /// Congestion window (bytes).
    cwnd: usize,
    /// Slow start threshold (bytes).
    ssthresh: usize,
    /// Remote window (bytes).
    rwnd: usize,
    /// Minimum congestion window.
    min_cwnd: usize,
    /// MSS (bytes).
    mss: usize,

    /// W_max: window at last loss event (bytes).
    w_max: usize,
    /// Time of last congestion event (ms).
    epoch_start: u64,
    /// K value: time to reach W_max from the cubic curve.
    k: f64,
    /// TCP-friendly window estimate (for Reno-like fallback).
    tcp_cwnd: usize,
    /// Origin point (W_max) for the cubic curve, in MSS units.
    origin_point: usize,

    /// ACK count for congestion avoidance.
    ack_count: usize,

    /// Whether we're in slow start.
    in_slow_start: bool,

    pub fn init(mss: u16) Cubic {
        const mss_usize = @as(usize, mss);
        const initial_cwnd = mss_usize * 10; // RFC 6928
        return Cubic{
            .cwnd = initial_cwnd,
            .ssthresh = std.math.maxInt(usize),
            .rwnd = 64 * 1024,
            .min_cwnd = mss_usize,
            .mss = mss_usize,
            .w_max = 0,
            .epoch_start = 0,
            .k = 0,
            .tcp_cwnd = initial_cwnd,
            .origin_point = 0,
            .ack_count = 0,
            .in_slow_start = true,
        };
    }

    /// Effective send window.
    pub fn window(self: *const Cubic) usize {
        return @min(self.cwnd, self.rwnd);
    }

    /// Called when bytes are acknowledged.
    pub fn onAck(self: *Cubic, now_ms: u64, acked_bytes: usize) void {
        if (self.cwnd < self.ssthresh) {
            // Slow start
            self.cwnd += acked_bytes;
            self.in_slow_start = true;
            return;
        }

        self.in_slow_start = false;

        // Initialize epoch if needed
        if (self.epoch_start == 0) {
            self.epoch_start = now_ms;
            if (self.cwnd < self.w_max) {
                // Compute K
                const w_max_mss = self.w_max / self.mss;
                const cwnd_mss = self.cwnd / self.mss;
                if (w_max_mss > cwnd_mss) {
                    const diff = @as(f64, @floatFromInt(w_max_mss - cwnd_mss));
                    self.k = std.math.cbrt(diff / C);
                } else {
                    self.k = 0;
                }
                self.origin_point = self.w_max;
            } else {
                self.k = 0;
                self.origin_point = self.cwnd;
            }
            self.tcp_cwnd = self.cwnd;
            self.ack_count = 0;
        }

        // Time since epoch in seconds
        const t_ms = now_ms - self.epoch_start;
        const t: f64 = @as(f64, @floatFromInt(t_ms)) / 1000.0;

        // CUBIC target: W(t) = C * (t - K)^3 + W_max (in bytes)
        const t_minus_k = t - self.k;
        const cubic_val = C * t_minus_k * t_minus_k * t_minus_k;
        const target_mss_f = cubic_val + @as(f64, @floatFromInt(self.origin_point / self.mss));
        const target = @as(usize, @intFromFloat(@max(target_mss_f, 0))) * self.mss;

        // TCP-friendly estimation (Reno)
        // W_tcp(t) = W_max * beta + 3 * (1-beta)/(1+beta) * t/RTT
        // Simplified: just increase by MSS per RTT
        self.ack_count += acked_bytes;
        if (self.ack_count >= self.cwnd) {
            self.tcp_cwnd += self.mss;
            self.ack_count = 0;
        }

        // Use max of cubic and TCP-friendly
        const new_cwnd = @max(target, self.tcp_cwnd);

        if (new_cwnd > self.cwnd) {
            // Increase gradually
            const increment = (new_cwnd - self.cwnd) * self.mss / self.cwnd;
            self.cwnd += @max(increment, 1);
        }

        self.cwnd = @max(self.cwnd, self.min_cwnd);
    }

    /// Called on retransmission timeout.
    pub fn onRetransmit(self: *Cubic) void {
        // Severe: reset to 1 MSS
        self.epoch_start = 0;
        self.w_max = self.cwnd;
        self.ssthresh = @max(@as(usize, @intCast(@as(u64, self.cwnd) * BETA_SCALE / 10)), self.min_cwnd * 2);
        self.cwnd = self.min_cwnd;
        self.in_slow_start = false;
    }

    /// Called on duplicate ACK (fast retransmit/recovery).
    pub fn onDuplicateAck(self: *Cubic) void {
        // Multiplicative decrease: W_max = cwnd, cwnd = cwnd * beta
        self.epoch_start = 0;
        self.w_max = self.cwnd;
        self.ssthresh = @max(@as(usize, @intCast(@as(u64, self.cwnd) * BETA_SCALE / 10)), self.min_cwnd * 2);
        self.cwnd = self.ssthresh;
    }

    /// Set remote window.
    pub fn setRemoteWindow(self: *Cubic, rwnd: usize) void {
        self.rwnd = @max(rwnd, self.min_cwnd);
    }

    /// Set MSS.
    pub fn setMss(self: *Cubic, mss: u16) void {
        self.mss = @as(usize, mss);
        self.min_cwnd = @as(usize, mss);
    }

    /// Inflate cwnd by one MSS (for each additional dup-ACK during Fast Recovery).
    pub fn inflateCwnd(self: *Cubic) void {
        self.cwnd += self.mss;
    }

    /// Deflate cwnd to ssthresh (on exiting Fast Recovery).
    pub fn deflateCwnd(self: *Cubic) void {
        self.cwnd = self.ssthresh;
    }

    /// Partial ACK during Fast Recovery (RFC 6582 §3.2).
    pub fn onPartialAck(self: *Cubic, acked_bytes: usize) void {
        if (self.cwnd > acked_bytes) {
            self.cwnd -= acked_bytes;
        } else {
            self.cwnd = self.min_cwnd;
        }
        self.cwnd += self.mss;
        self.cwnd = @max(self.cwnd, self.min_cwnd);
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Cubic: slow start" {
    var cc = Cubic.init(1460);
    const initial = cc.window();

    cc.onAck(100, 1460);
    try testing.expect(cc.window() > initial);
    try testing.expect(cc.in_slow_start);
}

test "Cubic: congestion avoidance growth" {
    var cc = Cubic.init(1460);
    cc.ssthresh = 10000;
    cc.cwnd = 20000;
    cc.w_max = 30000;

    const before = cc.cwnd;
    // Simulate time passing and ACKs
    cc.onAck(1000, 1460);
    cc.onAck(2000, 1460);
    cc.onAck(3000, 1460);

    try testing.expect(cc.cwnd >= before);
    try testing.expect(!cc.in_slow_start);
}

test "Cubic: multiplicative decrease on dup ACK" {
    var cc = Cubic.init(1460);
    cc.cwnd = 100_000;
    cc.ssthresh = 50_000;

    cc.onDuplicateAck();
    // cwnd should be reduced to ~70% (beta=0.7)
    try testing.expect(cc.cwnd < 100_000);
    try testing.expect(cc.cwnd >= 70_000);
    try testing.expectEqual(cc.cwnd, cc.ssthresh);
}

test "Cubic: retransmit resets to 1 MSS" {
    var cc = Cubic.init(1460);
    cc.cwnd = 100_000;

    cc.onRetransmit();
    try testing.expectEqual(@as(usize, 1460), cc.cwnd);
    try testing.expect(cc.w_max == 100_000);
}

test "Cubic: window never below min_cwnd" {
    var cc = Cubic.init(1460);
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        cc.onRetransmit();
    }
    try testing.expect(cc.window() >= 1460);
}

test "Cubic: convergence towards W_max" {
    var cc = Cubic.init(1460);
    cc.ssthresh = 50_000;
    cc.cwnd = 50_000;
    cc.w_max = 100_000;

    // Simulate many ACKs over time
    var t: u64 = 0;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        t += 100; // 100ms per ACK
        cc.onAck(t, 1460);
    }
    // Should be approaching w_max
    try testing.expect(cc.cwnd > 50_000);
}
