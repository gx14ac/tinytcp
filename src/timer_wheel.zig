// Timer wheel: efficient timer management for many TCP connections.
//
// Sans-IO, fixed capacity (comptime), O(1) schedule/cancel.
// Single-level hashed wheel with millisecond resolution.
//
// Integration plan: FullStack.poll() currently does O(max_conns) linear scan
// every tick. To use this wheel, Connection needs a `nextEventMs() ?u64` method
// so FullStack can schedule/reschedule per-connection timers on state changes.
// Then poll() becomes: advance wheel → process only fired timers.
// Prerequisite: Connection exposes next-event time (retx, delayed-ack, keepalive).

const std = @import("std");

pub const TimerCallback = struct {
    context: u16 = 0,
    id: u16 = 0,
};

pub const TimerHandle = u32;
const INVALID_HANDLE: u32 = std.math.maxInt(u32);

pub fn TimerWheel(comptime num_slots: usize, comptime max_timers: usize) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            callback: TimerCallback = .{},
            expiry_ms: u64 = 0,
            slot: u16 = 0,
            active: bool = false,
            next: u32 = INVALID_HANDLE,
            prev: u32 = INVALID_HANDLE,
        };

        entries: [max_timers]Entry = [_]Entry{.{}} ** max_timers,
        slots: [num_slots]u32 = [_]u32{INVALID_HANDLE} ** num_slots,
        free_head: u32 = 0,
        current_tick: u64 = 0,
        fired_head: u32 = INVALID_HANDLE,
        active_count: usize = 0,

        pub fn init(now_ms: u64) Self {
            var self = Self{};
            self.current_tick = now_ms;
            // Build free list
            var i: u32 = 0;
            while (i < max_timers - 1) : (i += 1) {
                self.entries[i].next = i + 1;
            }
            self.entries[max_timers - 1].next = INVALID_HANDLE;
            return self;
        }

        pub fn schedule(self: *Self, now_ms: u64, delay_ms: u64, callback: TimerCallback) ?TimerHandle {
            if (self.free_head == INVALID_HANDLE) return null;

            const handle = self.free_head;
            self.free_head = self.entries[handle].next;

            const expiry = now_ms + delay_ms;
            const slot: u16 = @intCast(expiry % num_slots);

            const entry = &self.entries[handle];
            entry.* = Entry{
                .callback = callback,
                .expiry_ms = expiry,
                .slot = slot,
                .active = true,
                .next = self.slots[slot],
                .prev = INVALID_HANDLE,
            };

            if (self.slots[slot] != INVALID_HANDLE) {
                self.entries[self.slots[slot]].prev = handle;
            }
            self.slots[slot] = handle;
            self.active_count += 1;

            return handle;
        }

        pub fn cancel(self: *Self, handle: TimerHandle) void {
            if (handle >= max_timers) return;
            var entry = &self.entries[handle];
            if (!entry.active) return;

            self.unlinkEntry(handle);
            entry.active = false;
            entry.next = self.free_head;
            self.free_head = handle;
            self.active_count -= 1;
        }

        pub const TimerIterator = struct {
            wheel: *Self,
            current: u32,

            pub fn next(self: *TimerIterator) ?TimerCallback {
                while (self.current != INVALID_HANDLE) {
                    const handle = self.current;
                    self.current = self.wheel.entries[handle].next;
                    const cb = self.wheel.entries[handle].callback;

                    // Return to free list
                    self.wheel.entries[handle].active = false;
                    self.wheel.entries[handle].next = self.wheel.free_head;
                    self.wheel.free_head = handle;
                    self.wheel.active_count -= 1;

                    return cb;
                }
                return null;
            }
        };

        pub fn advance(self: *Self, now_ms: u64) TimerIterator {
            self.fired_head = INVALID_HANDLE;
            var fired_tail: u32 = INVALID_HANDLE;

            while (self.current_tick <= now_ms) {
                const slot: usize = @intCast(self.current_tick % num_slots);
                var idx = self.slots[slot];
                while (idx != INVALID_HANDLE) {
                    const entry = &self.entries[idx];
                    const next_idx = entry.next;

                    if (entry.expiry_ms <= now_ms) {
                        // Remove from slot
                        if (entry.prev != INVALID_HANDLE) {
                            self.entries[entry.prev].next = entry.next;
                        } else {
                            self.slots[slot] = entry.next;
                        }
                        if (entry.next != INVALID_HANDLE) {
                            self.entries[entry.next].prev = entry.prev;
                        }

                        // Add to fired list
                        entry.next = INVALID_HANDLE;
                        entry.prev = INVALID_HANDLE;
                        if (self.fired_head == INVALID_HANDLE) {
                            self.fired_head = idx;
                        } else {
                            self.entries[fired_tail].next = idx;
                        }
                        fired_tail = idx;
                    }

                    idx = next_idx;
                }
                self.current_tick += 1;
            }
            self.current_tick = now_ms;

            return TimerIterator{ .wheel = self, .current = self.fired_head };
        }

        pub fn nextExpiry(self: *const Self) ?u64 {
            var earliest: ?u64 = null;
            for (&self.entries) |*entry| {
                if (entry.active) {
                    if (earliest == null or entry.expiry_ms < earliest.?) {
                        earliest = entry.expiry_ms;
                    }
                }
            }
            return earliest;
        }

        fn unlinkEntry(self: *Self, handle: u32) void {
            const entry = &self.entries[handle];
            const slot = entry.slot;
            if (entry.prev != INVALID_HANDLE) {
                self.entries[entry.prev].next = entry.next;
            } else {
                self.slots[slot] = entry.next;
            }
            if (entry.next != INVALID_HANDLE) {
                self.entries[entry.next].prev = entry.prev;
            }
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "TimerWheel: schedule and fire" {
    var wheel = TimerWheel(64, 16).init(0);
    const h = wheel.schedule(0, 10, .{ .context = 1, .id = 2 }).?;
    _ = h;

    // Not fired at t=9
    var it = wheel.advance(9);
    try testing.expect(it.next() == null);

    // Fired at t=10
    it = wheel.advance(10);
    const cb = it.next().?;
    try testing.expectEqual(@as(u16, 1), cb.context);
    try testing.expectEqual(@as(u16, 2), cb.id);
    try testing.expect(it.next() == null);
}

test "TimerWheel: cancel before expiry" {
    var wheel = TimerWheel(64, 16).init(0);
    const h = wheel.schedule(0, 50, .{ .context = 5, .id = 0 }).?;

    wheel.cancel(h);

    var it = wheel.advance(100);
    try testing.expect(it.next() == null);
}

test "TimerWheel: multiple timers" {
    var wheel = TimerWheel(64, 16).init(0);
    _ = wheel.schedule(0, 5, .{ .context = 1, .id = 0 });
    _ = wheel.schedule(0, 10, .{ .context = 2, .id = 0 });
    _ = wheel.schedule(0, 15, .{ .context = 3, .id = 0 });

    var it = wheel.advance(10);
    var count: usize = 0;
    while (it.next()) |_| {
        count += 1;
    }
    try testing.expectEqual(@as(usize, 2), count);

    it = wheel.advance(15);
    const cb = it.next().?;
    try testing.expectEqual(@as(u16, 3), cb.context);
}

test "TimerWheel: pool exhaustion" {
    var wheel = TimerWheel(64, 2).init(0);
    try testing.expect(wheel.schedule(0, 10, .{}) != null);
    try testing.expect(wheel.schedule(0, 20, .{}) != null);
    try testing.expect(wheel.schedule(0, 30, .{}) == null); // full
}

test "TimerWheel: nextExpiry" {
    var wheel = TimerWheel(64, 16).init(0);
    try testing.expect(wheel.nextExpiry() == null);

    _ = wheel.schedule(0, 50, .{});
    _ = wheel.schedule(0, 20, .{});
    _ = wheel.schedule(0, 100, .{});

    try testing.expectEqual(@as(u64, 20), wheel.nextExpiry().?);
}

test "TimerWheel: reuse after fire" {
    var wheel = TimerWheel(64, 2).init(0);
    _ = wheel.schedule(0, 5, .{ .context = 1, .id = 0 });
    _ = wheel.schedule(0, 5, .{ .context = 2, .id = 0 });

    // Fire both
    var it = wheel.advance(5);
    while (it.next()) |_| {}

    // Should be able to schedule again
    try testing.expect(wheel.schedule(5, 10, .{ .context = 3, .id = 0 }) != null);
    try testing.expect(wheel.schedule(5, 10, .{ .context = 4, .id = 0 }) != null);
}
