// RTT Estimator (RFC 6298).
//
// Maintains SRTT, RTTVAR, and computes RTO.
// Used by the TCP sender to determine retransmission timeouts.

const std = @import("std");

/// Initial RTO (RFC 6298 section 2.1): 1 second.
const initial_rto_ms: u32 = 1000;

/// Minimum RTO (RFC 6298 section 2.4): 1 second.
const min_rto_ms: u32 = 1000;

/// Maximum RTO (RFC 6298 section 2.5): 60 seconds.
const max_rto_ms: u32 = 60_000;

/// Minimum safety margin for RTO (accounts for delayed ACKs).
const min_rto_margin_ms: u32 = 200;

pub const RttEstimator = struct {
    /// Smoothed RTT (in milliseconds), or null if no sample yet.
    srtt: ?u32 = null,

    /// RTT variance (in milliseconds).
    rttvar: u32 = 0,

    /// Current RTO (in milliseconds).
    rto: u32 = initial_rto_ms,

    /// Number of consecutive retransmissions (for exponential backoff).
    retransmit_count: u8 = 0,

    /// Whether we're currently timing a segment (sampling).
    sampling: bool = false,

    /// Timestamp when the sample segment was sent.
    sample_sent_at: u64 = 0,

    /// Sequence number of the segment being timed.
    sample_seq: u32 = 0,

    /// Get the current RTO in milliseconds.
    pub fn rtoMs(self: *const RttEstimator) u32 {
        return self.rto;
    }

    /// Begin timing a segment for RTT measurement.
    pub fn startSample(self: *RttEstimator, now_ms: u64, seq: u32) void {
        if (!self.sampling) {
            self.sampling = true;
            self.sample_sent_at = now_ms;
            self.sample_seq = seq;
        }
    }

    /// Feed an explicit RTT sample (e.g., from TCP Timestamps).
    pub fn update(self: *RttEstimator, sample_ms: u64) void {
        self.retransmit_count = 0;
        self.updateRtt(@intCast(@min(sample_ms, std.math.maxInt(u32))));
    }

    /// Process an ACK. If it acknowledges our timed segment, compute RTT.
    pub fn onAck(self: *RttEstimator, now_ms: u64, ack_seq: u32) void {
        self.retransmit_count = 0;

        // Check if this ACK completes our sample
        if (self.sampling and seqGte(ack_seq, self.sample_seq)) {
            const rtt_sample = @as(u32, @intCast(now_ms - self.sample_sent_at));
            self.updateRtt(rtt_sample);
            self.sampling = false;
        }
    }

    /// Update SRTT/RTTVAR/RTO based on a new RTT sample (RFC 6298).
    fn updateRtt(self: *RttEstimator, sample_ms: u32) void {
        if (self.srtt) |srtt| {
            // RFC 6298 (2.3): subsequent measurements
            // RTTVAR = (1-beta) * RTTVAR + beta * |SRTT - R'|  (beta = 1/4)
            const diff = if (sample_ms > srtt) sample_ms - srtt else srtt - sample_ms;
            self.rttvar = (self.rttvar * 3 + diff) / 4;
            // SRTT = (1-alpha) * SRTT + alpha * R'  (alpha = 1/8)
            self.srtt = (srtt * 7 + sample_ms) / 8;
        } else {
            // RFC 6298 (2.2): first measurement
            self.srtt = sample_ms;
            self.rttvar = sample_ms / 2;
        }

        // RFC 6298 (2.3): RTO = SRTT + max(G, K*RTTVAR) where K=4
        const margin = @max(min_rto_margin_ms, self.rttvar * 4);
        self.rto = std.math.clamp(self.srtt.? + margin, min_rto_ms, max_rto_ms);
    }

    /// Called on retransmission timeout: exponential backoff (RFC 6298 section 5.5).
    pub fn onRetransmit(self: *RttEstimator) void {
        // Cancel any ongoing sample (Karn's algorithm)
        self.sampling = false;

        // Double the RTO (exponential backoff)
        self.rto = @min(self.rto * 2, max_rto_ms);
        self.retransmit_count +|= 1;
    }

    /// Reset to initial state.
    pub fn reset(self: *RttEstimator) void {
        self.* = .{};
    }
};

/// Sequence number >= comparison (wrapping).
fn seqGte(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) >= 0;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "RttEstimator: first sample" {
    var rtt = RttEstimator{};

    rtt.startSample(0, 1000);
    rtt.onAck(100, 1001); // 100ms RTT

    try testing.expectEqual(@as(?u32, 100), rtt.srtt);
    try testing.expectEqual(@as(u32, 50), rtt.rttvar);
    // RTO = 100 + max(200, 50*4) = 100 + 200 = 300 → clamped to min 1000
    try testing.expectEqual(@as(u32, 1000), rtt.rto);
}

test "RttEstimator: subsequent samples" {
    var rtt = RttEstimator{};

    // First sample: 100ms
    rtt.startSample(0, 1000);
    rtt.onAck(100, 1001);

    // Second sample: 120ms
    rtt.startSample(200, 2000);
    rtt.onAck(320, 2001);

    // SRTT = (100*7 + 120) / 8 = 102 (approx)
    // RTTVAR = (50*3 + |100-120|) / 4 = (150+20)/4 = 42
    try testing.expect(rtt.srtt.? >= 100 and rtt.srtt.? <= 105);
}

test "RttEstimator: exponential backoff" {
    var rtt = RttEstimator{};
    try testing.expectEqual(@as(u32, 1000), rtt.rto);

    rtt.onRetransmit();
    try testing.expectEqual(@as(u32, 2000), rtt.rto);

    rtt.onRetransmit();
    try testing.expectEqual(@as(u32, 4000), rtt.rto);

    rtt.onRetransmit();
    try testing.expectEqual(@as(u32, 8000), rtt.rto);
}

test "RttEstimator: max RTO cap" {
    var rtt = RttEstimator{};
    // Keep backing off until we hit the cap
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        rtt.onRetransmit();
    }
    try testing.expectEqual(max_rto_ms, rtt.rto);
}

test "RttEstimator: Karn's algorithm cancels sample on retransmit" {
    var rtt = RttEstimator{};
    rtt.startSample(0, 1000);
    try testing.expect(rtt.sampling);

    rtt.onRetransmit(); // should cancel
    try testing.expect(!rtt.sampling);
}

test "RttEstimator: explicit update from timestamps" {
    var rtt = RttEstimator{};

    // First explicit sample: 80ms
    rtt.update(80);
    try testing.expectEqual(@as(?u32, 80), rtt.srtt);
    try testing.expectEqual(@as(u32, 40), rtt.rttvar);
    try testing.expectEqual(@as(u8, 0), rtt.retransmit_count);

    // Second explicit sample: 100ms
    rtt.update(100);
    // SRTT = (80*7 + 100)/8 = 82
    try testing.expect(rtt.srtt.? >= 80 and rtt.srtt.? <= 85);
}
