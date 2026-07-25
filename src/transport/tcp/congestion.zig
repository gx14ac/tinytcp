// Congestion Control for TCP.
//
// Implements pluggable congestion control via tagged union.
// Currently supports: Reno, None (unlimited).
// CUBIC to be added later.
//
// Interface inspired by smoltcp's Controller trait:
// - window(): current congestion window
// - onAck(): called when new data is acknowledged
// - onRetransmit(): called on retransmission timeout
// - onDuplicateAck(): called on receiving duplicate ACKs (fast retransmit)

const std = @import("std");
const cubic_mod = @import("cubic.zig");
const bbr_mod = @import("bbr.zig");

pub const Cubic = cubic_mod.Cubic;
pub const Bbr = bbr_mod.Bbr;

/// Congestion control algorithm selection.
pub const Algorithm = enum {
    none,
    reno,
    cubic,
    bbr,
};

/// Congestion controller (tagged union for compile-time polymorphism).
pub const Controller = union(Algorithm) {
    none: NoControl,
    reno: Reno,
    cubic: Cubic,
    bbr: Bbr,

    pub fn init(algo: Algorithm, mss: u16) Controller {
        return switch (algo) {
            .none => .{ .none = NoControl.init() },
            .reno => .{ .reno = Reno.init(mss) },
            .cubic => .{ .cubic = Cubic.init(mss) },
            .bbr => .{ .bbr = Bbr.init(mss) },
        };
    }

    /// Current send window (in bytes).
    pub fn window(self: *const Controller) usize {
        return switch (self.*) {
            .none => |*n| n.window(),
            .reno => |*r| r.window(),
            .cubic => |*c| c.window(),
            .bbr => |*b| b.window(),
        };
    }

    /// Called when bytes are acknowledged (without timestamp; uses 0 for time-based algorithms).
    pub fn onAck(self: *Controller, acked_bytes: usize) void {
        self.onAckWithTime(0, acked_bytes);
    }

    /// Called when bytes are acknowledged (with timestamp for CUBIC/BBR).
    pub fn onAckWithTime(self: *Controller, now_ms: u64, acked_bytes: usize) void {
        switch (self.*) {
            .none => {},
            .reno => |*r| r.onAck(acked_bytes),
            .cubic => |*c| c.onAck(now_ms, acked_bytes),
            .bbr => |*b| b.onAck(now_ms, acked_bytes),
        }
    }

    /// Called when bytes are acknowledged with per-packet BBR delivery state and RTT.
    /// For non-BBR algorithms, delegates to the simple path.
    pub fn onAckBbr(self: *Controller, now_ms: u64, acked_bytes: usize, pkt_delivered: u64, pkt_delivered_time: u64, rtt_ms: u64) void {
        switch (self.*) {
            .bbr => |*b| b.onAckDetailed(now_ms, .{
                .bytes = acked_bytes,
                .rtt_ms = rtt_ms,
                .send_state = .{ .delivered = pkt_delivered, .delivered_time = pkt_delivered_time },
            }),
            .none => {},
            .reno => |*r| r.onAck(acked_bytes),
            .cubic => |*c| c.onAck(now_ms, acked_bytes),
        }
    }

    /// Called on retransmission timeout.
    pub fn onRetransmit(self: *Controller) void {
        switch (self.*) {
            .none => {},
            .reno => |*r| r.onRetransmit(),
            .cubic => |*c| c.onRetransmit(),
            .bbr => |*b| b.onRetransmit(),
        }
    }

    /// Called on duplicate ACK (potential fast retransmit).
    pub fn onDuplicateAck(self: *Controller) void {
        switch (self.*) {
            .none => {},
            .reno => |*r| r.onDuplicateAck(),
            .cubic => |*c| c.onDuplicateAck(),
            .bbr => |*b| b.onDuplicateAck(),
        }
    }

    /// Called on ECN Congestion Experienced (CE) signal (RFC 3168).
    /// Same multiplicative decrease as loss but no retransmission.
    pub fn onEcnCe(self: *Controller) void {
        switch (self.*) {
            .none => {},
            .reno => |*r| r.onEcnCe(),
            .cubic => |*c| c.onDuplicateAck(),
            .bbr => |*b| b.onEcnCe(),
        }
    }

    /// Called when bytes are sent (tracks inflight for BBR).
    pub fn onSend(self: *Controller, bytes: usize) void {
        switch (self.*) {
            .bbr => |*b| b.onSend(bytes),
            else => {},
        }
    }

    /// Inflate cwnd by one MSS (NewReno: each additional dup-ACK during Fast Recovery).
    pub fn inflateCwnd(self: *Controller) void {
        switch (self.*) {
            .none => {},
            .reno => |*r| r.inflateCwnd(),
            .cubic => |*c| c.inflateCwnd(),
            .bbr => |*b| b.inflateCwnd(),
        }
    }

    /// Deflate cwnd to ssthresh (NewReno: exiting Fast Recovery on full ACK).
    pub fn deflateCwnd(self: *Controller) void {
        switch (self.*) {
            .none => {},
            .reno => |*r| r.deflateCwnd(),
            .cubic => |*c| c.deflateCwnd(),
            .bbr => |*b| b.deflateCwnd(),
        }
    }

    /// Partial ACK deflation (NewReno RFC 6582 §3.2):
    /// cwnd -= acked_bytes, cwnd += MSS (allows sending one new segment).
    pub fn onPartialAck(self: *Controller, acked_bytes: usize) void {
        switch (self.*) {
            .none => {},
            .reno => |*r| r.onPartialAck(acked_bytes),
            .cubic => |*c| c.onPartialAck(acked_bytes),
            .bbr => |*b| b.onPartialAck(acked_bytes),
        }
    }

    /// Set the remote window size.
    pub fn setRemoteWindow(self: *Controller, rwnd: usize) void {
        switch (self.*) {
            .none => {},
            .reno => |*r| r.setRemoteWindow(rwnd),
            .cubic => |*c| c.setRemoteWindow(rwnd),
            .bbr => |*b| b.setRemoteWindow(rwnd),
        }
    }

    /// Set the MSS.
    pub fn setMss(self: *Controller, mss: u16) void {
        switch (self.*) {
            .none => {},
            .reno => |*r| r.setMss(mss),
            .cubic => |*c| c.setMss(mss),
            .bbr => |*b| b.setMss(mss),
        }
    }
};

/// No congestion control (unlimited sending).
pub const NoControl = struct {
    pub fn init() NoControl {
        return .{};
    }

    pub fn window(_: *const NoControl) usize {
        return std.math.maxInt(usize);
    }
};

/// Reno congestion control (RFC 5681).
/// Implements slow start and congestion avoidance.
pub const Reno = struct {
    /// Congestion window (bytes).
    cwnd: usize,
    /// Slow start threshold (bytes).
    ssthresh: usize,
    /// Remote window (bytes).
    rwnd: usize,
    /// Minimum congestion window (1 MSS).
    min_cwnd: usize,

    pub fn init(mss: u16) Reno {
        const initial_cwnd = @as(usize, mss) * 10; // RFC 6928: IW=10
        return Reno{
            .cwnd = initial_cwnd,
            .ssthresh = std.math.maxInt(usize),
            .rwnd = 64 * 1024,
            .min_cwnd = @as(usize, mss),
        };
    }

    pub fn window(self: *const Reno) usize {
        return @min(self.cwnd, self.rwnd);
    }

    pub fn onAck(self: *Reno, acked_bytes: usize) void {
        if (self.cwnd < self.ssthresh) {
            // Slow start: increase cwnd by acked bytes (exponential growth)
            self.cwnd = @min(self.cwnd + acked_bytes, self.rwnd);
        } else {
            // Congestion avoidance: increase cwnd by MSS^2/cwnd per ACK (linear growth)
            const increment = @max(self.min_cwnd * self.min_cwnd / self.cwnd, 1);
            self.cwnd = @min(self.cwnd + increment, self.rwnd);
        }
        self.cwnd = @max(self.cwnd, self.min_cwnd);
    }

    pub fn onRetransmit(self: *Reno) void {
        // RFC 5681: ssthresh = max(FlightSize/2, 2*MSS)
        self.ssthresh = @max(self.cwnd / 2, self.min_cwnd * 2);
        // Reset cwnd to 1 MSS (or IW)
        self.cwnd = self.min_cwnd;
    }

    pub fn onDuplicateAck(self: *Reno) void {
        // Fast retransmit: ssthresh = cwnd/2, cwnd = ssthresh + 3*MSS
        self.ssthresh = @max(self.cwnd / 2, self.min_cwnd * 2);
        self.cwnd = self.ssthresh + self.min_cwnd * 3;
    }

    /// ECN CE: reduce cwnd like fast retransmit but without inflation.
    pub fn onEcnCe(self: *Reno) void {
        self.ssthresh = @max(self.cwnd / 2, self.min_cwnd * 2);
        self.cwnd = self.ssthresh;
    }

    /// Inflate cwnd by one MSS (for each additional dup-ACK during Fast Recovery).
    pub fn inflateCwnd(self: *Reno) void {
        self.cwnd += self.min_cwnd;
    }

    /// Deflate cwnd to ssthresh (on exiting Fast Recovery).
    pub fn deflateCwnd(self: *Reno) void {
        self.cwnd = self.ssthresh;
    }

    /// Partial ACK during Fast Recovery (RFC 6582 §3.2):
    /// Deflate by acked amount (removes inflation for those segments), add MSS.
    pub fn onPartialAck(self: *Reno, acked_bytes: usize) void {
        if (self.cwnd > acked_bytes) {
            self.cwnd -= acked_bytes;
        } else {
            self.cwnd = self.min_cwnd;
        }
        self.cwnd += self.min_cwnd;
        self.cwnd = @max(self.cwnd, self.min_cwnd);
    }

    pub fn setRemoteWindow(self: *Reno, rwnd: usize) void {
        self.rwnd = @max(rwnd, self.min_cwnd);
    }

    pub fn setMss(self: *Reno, mss: u16) void {
        self.min_cwnd = @as(usize, mss);
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Reno: slow start" {
    var cc = Controller.init(.reno, 1460);
    const initial_window = cc.window();

    // ACK 1460 bytes → cwnd should increase
    cc.onAck(1460);
    try testing.expect(cc.window() > initial_window);
}

test "Reno: congestion avoidance" {
    var reno = Reno.init(1460);
    // Set ssthresh below cwnd to enter CA mode
    reno.ssthresh = 5000;
    reno.cwnd = 10000;

    const before = reno.cwnd;
    reno.onAck(1460);
    // In CA, growth should be small (linear)
    try testing.expect(reno.cwnd > before);
    try testing.expect(reno.cwnd - before < 1460); // Less than 1 MSS increase
}

test "Reno: retransmit halves window" {
    var cc = Controller.init(.reno, 1460);
    // Grow the window first
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        cc.onAck(1460);
    }
    const before = cc.window();
    cc.onRetransmit();
    // After retransmit, cwnd should drop to min_cwnd
    try testing.expect(cc.window() < before);
}

test "Reno: duplicate ACK fast retransmit" {
    var cc = Controller.init(.reno, 1460);
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        cc.onAck(1460);
    }
    const before = cc.window();
    cc.onDuplicateAck();
    // After dup ACK: ssthresh = cwnd/2, cwnd = ssthresh + 3*MSS
    // window() = min(cwnd, rwnd)
    _ = before;
    try testing.expect(cc.window() > 0);
}

test "NoControl: unlimited window" {
    const cc = Controller.init(.none, 1460);
    try testing.expectEqual(std.math.maxInt(usize), cc.window());
}

test "Reno: window never below min_cwnd" {
    var cc = Controller.init(.reno, 1460);
    // Multiple retransmits
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        cc.onRetransmit();
    }
    try testing.expect(cc.window() >= 1460);
}
