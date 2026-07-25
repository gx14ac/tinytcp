// TCP Timer state machine.
//
// Manages retransmission, delayed ACK, keepalive, and TIME-WAIT timers.
// Sans-IO: timers don't run themselves — caller polls for the next deadline.
//
// Modeled after smoltcp's Timer enum.

const std = @import("std");

/// TIME-WAIT duration: 2*MSL (RFC 9293). MSL = 60s → 120s.
pub const time_wait_duration_ms: u64 = 120_000;

/// Default keepalive interval: 75 seconds.
pub const keepalive_interval_ms: u64 = 75_000;

/// Delayed ACK timeout: 40ms (Linux default).
pub const delayed_ack_ms: u64 = 40;

/// Maximum retransmission attempts before giving up.
pub const max_retransmits: u8 = 15;

/// Timer state for a TCP connection.
pub const Timer = union(enum) {
    /// No timer active; connection is idle or keepalive pending.
    idle: struct {
        /// When to send next keepalive (0 = disabled).
        keepalive_at: u64 = 0,
    },

    /// Retransmission timer is running.
    retransmit: struct {
        /// When the timer expires.
        expires_at: u64,
        /// Number of retransmissions so far.
        count: u8 = 0,
    },

    /// Fast retransmit requested (3 duplicate ACKs).
    fast_retransmit,

    /// Delayed ACK timer.
    delayed_ack: struct {
        expires_at: u64,
    },

    /// TIME-WAIT timer (waiting for 2*MSL before CLOSED).
    time_wait: struct {
        expires_at: u64,
    },

    /// Zero window probe timer.
    zero_window_probe: struct {
        expires_at: u64,
    },

    /// Check if any timer needs firing at the given timestamp.
    pub fn shouldFire(self: *const Timer, now_ms: u64) bool {
        return switch (self.*) {
            .idle => |idle| idle.keepalive_at > 0 and now_ms >= idle.keepalive_at,
            .retransmit => |rt| now_ms >= rt.expires_at,
            .fast_retransmit => true,
            .delayed_ack => |da| now_ms >= da.expires_at,
            .time_wait => |tw| now_ms >= tw.expires_at,
            .zero_window_probe => |zwp| now_ms >= zwp.expires_at,
        };
    }

    /// Get the next time we need to poll (earliest deadline).
    /// Returns null if no timer is active.
    pub fn nextPollAt(self: *const Timer) ?u64 {
        return switch (self.*) {
            .idle => |idle| if (idle.keepalive_at > 0) idle.keepalive_at else null,
            .retransmit => |rt| rt.expires_at,
            .fast_retransmit => 0, // poll immediately
            .delayed_ack => |da| da.expires_at,
            .time_wait => |tw| tw.expires_at,
            .zero_window_probe => |zwp| zwp.expires_at,
        };
    }

    /// Set the retransmit timer with a given RTO.
    pub fn setRetransmit(self: *Timer, now_ms: u64, rto_ms: u32) void {
        switch (self.*) {
            .time_wait => {}, // don't override TIME-WAIT
            else => {
                const count: u8 = switch (self.*) {
                    .retransmit => |rt| rt.count,
                    else => 0,
                };
                self.* = .{ .retransmit = .{
                    .expires_at = now_ms + @as(u64, rto_ms),
                    .count = count,
                } };
            },
        }
    }

    /// Mark as needing fast retransmit (3 dup ACKs).
    pub fn setFastRetransmit(self: *Timer) void {
        switch (self.*) {
            .time_wait => {},
            else => {
                self.* = .fast_retransmit;
            },
        }
    }

    /// Set delayed ACK timer.
    pub fn setDelayedAck(self: *Timer, now_ms: u64) void {
        switch (self.*) {
            .retransmit, .fast_retransmit => {}, // retransmit takes priority
            .time_wait => {},
            else => {
                self.* = .{ .delayed_ack = .{
                    .expires_at = now_ms + delayed_ack_ms,
                } };
            },
        }
    }

    /// Set TIME-WAIT timer.
    pub fn setTimeWait(self: *Timer, now_ms: u64) void {
        self.* = .{ .time_wait = .{
            .expires_at = now_ms + time_wait_duration_ms,
        } };
    }

    /// Set zero window probe timer.
    pub fn setZeroWindowProbe(self: *Timer, now_ms: u64, rto_ms: u32) void {
        self.* = .{ .zero_window_probe = .{
            .expires_at = now_ms + @as(u64, rto_ms),
        } };
    }

    /// Acknowledge a retransmit (data was ACKed), go back to idle.
    pub fn onAck(self: *Timer) void {
        switch (self.*) {
            .retransmit, .fast_retransmit, .delayed_ack => {
                self.* = .{ .idle = .{} };
            },
            else => {},
        }
    }

    /// Increment retransmit count. Returns true if max retransmits exceeded.
    pub fn onRetransmitTimeout(self: *Timer, now_ms: u64, rto_ms: u32) bool {
        switch (self.*) {
            .retransmit => |*rt| {
                rt.count += 1;
                if (rt.count >= max_retransmits) return true;
                rt.expires_at = now_ms + @as(u64, rto_ms);
                return false;
            },
            else => return false,
        }
    }

    /// Reset to idle state.
    pub fn reset(self: *Timer) void {
        self.* = .{ .idle = .{} };
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Timer: retransmit fires" {
    var timer = Timer{ .idle = .{} };
    timer.setRetransmit(0, 1000); // fires at t=1000

    try testing.expect(!timer.shouldFire(500));
    try testing.expect(timer.shouldFire(1000));
    try testing.expect(timer.shouldFire(1500));
}

test "Timer: delayed ACK" {
    var timer = Timer{ .idle = .{} };
    timer.setDelayedAck(100); // fires at t=100+40=140

    try testing.expect(!timer.shouldFire(130));
    try testing.expect(timer.shouldFire(140));
}

test "Timer: TIME-WAIT" {
    var timer = Timer{ .idle = .{} };
    timer.setTimeWait(0);

    try testing.expect(!timer.shouldFire(60_000));
    try testing.expect(timer.shouldFire(120_000));
}

test "Timer: retransmit count and abort" {
    var timer = Timer{ .idle = .{} };
    timer.setRetransmit(0, 1000);

    // Simulate max_retransmits timeouts
    var i: u8 = 0;
    while (i < max_retransmits - 1) : (i += 1) {
        const aborted = timer.onRetransmitTimeout(1000 * @as(u64, i + 1), 1000);
        try testing.expect(!aborted);
    }
    // Next one should abort
    const aborted = timer.onRetransmitTimeout(100_000, 1000);
    try testing.expect(aborted);
}

test "Timer: fast retransmit fires immediately" {
    var timer = Timer{ .idle = .{} };
    timer.setFastRetransmit();
    try testing.expect(timer.shouldFire(0));
    try testing.expectEqual(@as(?u64, 0), timer.nextPollAt());
}

test "Timer: onAck resets to idle" {
    var timer = Timer{ .idle = .{} };
    timer.setRetransmit(0, 1000);
    timer.onAck();
    switch (timer) {
        .idle => {},
        else => return error.TestUnexpectedResult,
    }
}
