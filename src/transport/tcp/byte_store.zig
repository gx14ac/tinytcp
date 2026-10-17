// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

// ByteStore: where a connection keeps the bytes of one direction.
//
// Either a fixed array inside the connection (the default, and the only
// choice without an allocator), or memory from an allocator that grows to
// what the connection holds and goes back once it is drained. A
// connection that holds nothing then costs next to nothing, so the
// largest a buffer may grow to can be set for throughput — what is in
// flight is bounded by it — without every idle connection paying for it.
//
// The bytes are one contiguous run from the start, as the fixed array's
// were: callers address them by offset and move them down as the front is
// consumed. Growing keeps the first `keep` bytes where they are.

const std = @import("std");

/// An allocator that hands out no more than `limit` bytes at once, from
/// `parent`: what every connection's buffers hold together. Without it
/// what a stack holds is bounded only by connections times the largest a
/// buffer may grow to — 2048 × 512KiB is a gigabyte — and a peer, or a
/// host socket that stops reading, decides how much of that is taken.
/// Past the limit an allocation fails, which a ByteStore takes as it takes
/// any refusal: a write accepts less, a segment is not taken and comes
/// again. Not thread-safe: the stack it belongs to is not either.
pub const Budget = struct {
    parent: std.mem.Allocator,
    /// The most held at once. 0: no limit.
    limit: usize = 0,
    /// What is held now.
    used: usize = 0,

    pub fn allocator(self: *Budget) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: std.mem.Allocator.VTable = .{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn room(self: *const Budget, more: usize) bool {
        return self.limit == 0 or self.used + more <= self.limit;
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        if (!self.room(len)) return null;
        const p = self.parent.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.used += len;
        return p;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and !self.room(new_len - memory.len)) return false;
        if (!self.parent.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.used = self.used - memory.len + new_len;
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        if (new_len > memory.len and !self.room(new_len - memory.len)) return null;
        const p = self.parent.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.used = self.used - memory.len + new_len;
        return p;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(memory, alignment, ret_addr);
        self.used -= memory.len;
    }
};

pub fn ByteStore(comptime max: usize, comptime grow: bool, comptime initial: usize) type {
    return struct {
        const Self = @This();

        /// The most this store holds.
        pub const max_len: usize = max;
        /// What a grown store goes back to once drained.
        pub const initial_len: usize = @min(initial, max);

        fixed: if (grow) void else [max]u8 = if (grow) {} else undefined,
        heap: []u8 = &.{},
        /// Where a growing store's memory comes from. Null: it never grows,
        /// and holds nothing.
        allocator: ?std.mem.Allocator = null,

        /// The bytes there are room for now.
        pub fn slice(self: *Self) []u8 {
            return if (grow) self.heap else &self.fixed;
        }

        pub fn sliceConst(self: *const Self) []const u8 {
            return if (grow) self.heap else &self.fixed;
        }

        /// Room for `need` bytes, keeping the first `keep` as they are.
        /// False when there cannot be: past `max`, no allocator, or the
        /// allocator refused. Grows by doubling, so a stream that writes a
        /// little at a time does not copy everything each time — and to
        /// just `need` when doubling is refused, as it is near a Budget's
        /// limit.
        pub fn ensure(self: *Self, need: usize, keep: usize) bool {
            if (!grow) return need <= max;
            if (need <= self.heap.len) return true;
            if (need > max) return false;
            const a = self.allocator orelse return false;
            const doubled = @min(max, @max(need, @max(self.heap.len * 2, initial_len)));
            return self.growTo(a, doubled, keep) or (doubled > need and self.growTo(a, need, keep));
        }

        /// Room for as much of `need` as can be had: all of it, or, refused
        /// that, half the growth and half again, down to `initial_len` more
        /// than there is. What a write does short of memory: take part of
        /// what it was given, rather than none.
        pub fn ensureUpTo(self: *Self, need: usize, keep: usize) void {
            if (!grow or self.ensure(need, keep)) return;
            var want: usize = @min(need, max);
            while (want > self.heap.len + initial_len) {
                want = self.heap.len + (want - self.heap.len) / 2;
                if (self.ensure(want, keep)) return;
            }
        }

        /// In place, or moved whole, where the allocator can; otherwise a
        /// new run with the first `keep` bytes copied over.
        fn growTo(self: *Self, a: std.mem.Allocator, len: usize, keep: usize) bool {
            if (self.heap.len > 0) {
                if (a.remap(self.heap, len)) |moved| {
                    self.heap = moved;
                    return true;
                }
            }
            const fresh = a.alloc(u8, len) catch return false;
            const kept = @min(keep, self.heap.len);
            @memcpy(fresh[0..kept], self.heap[0..kept]);
            if (self.heap.len > 0) a.free(self.heap);
            self.heap = fresh;
            return true;
        }

        /// Whether shrink would give anything back.
        pub fn canShrink(self: *const Self, keep: usize) bool {
            return grow and self.heap.len > initial_len and keep <= initial_len;
        }

        /// Give back what is past `initial_len` once the first `keep`
        /// bytes fit in it: a connection that has drained goes back to
        /// costing little. Kept at `initial_len` rather than nothing, so a
        /// connection trading small requests does not allocate for each.
        /// In place where the allocator can; otherwise moved.
        pub fn shrink(self: *Self, keep: usize) void {
            if (!self.canShrink(keep)) return;
            const a = self.allocator orelse return;
            if (a.resize(self.heap, initial_len)) {
                self.heap = self.heap[0..initial_len];
                return;
            }
            // Nothing to keep: give back first. Allocating the small one
            // first needs room for both, and under a Budget that is full —
            // when giving back matters most — there is none.
            if (keep == 0) {
                a.free(self.heap);
                self.heap = a.alloc(u8, initial_len) catch &.{};
                return;
            }
            const fresh = a.alloc(u8, initial_len) catch return;
            @memcpy(fresh[0..keep], self.heap[0..keep]);
            a.free(self.heap);
            self.heap = fresh;
        }

        /// Give everything back. The store holds nothing after, and grows
        /// again if used.
        pub fn release(self: *Self) void {
            if (!grow) return;
            if (self.heap.len > 0) {
                if (self.allocator) |a| a.free(self.heap);
            }
            self.heap = &.{};
        }
    };
}

const testing = std.testing;

test "ByteStore: fixed holds max and never more" {
    var s = ByteStore(16, false, 4){};
    try testing.expectEqual(@as(usize, 16), s.slice().len);
    try testing.expect(s.ensure(16, 0));
    try testing.expect(!s.ensure(17, 0));
}

test "ByteStore: growing keeps what it holds, doubles, stops at max, and goes back" {
    var s = ByteStore(64, true, 8){ .allocator = testing.allocator };
    defer s.release();
    try testing.expectEqual(@as(usize, 0), s.slice().len);

    try testing.expect(s.ensure(3, 0));
    try testing.expectEqual(@as(usize, 8), s.slice().len);
    @memcpy(s.slice()[0..3], "abc");

    try testing.expect(s.ensure(9, 3));
    try testing.expectEqual(@as(usize, 16), s.slice().len); // doubled
    try testing.expectEqualStrings("abc", s.slice()[0..3]);

    try testing.expect(s.ensure(40, 3));
    try testing.expectEqual(@as(usize, 40), s.slice().len);
    try testing.expect(!s.ensure(65, 3));
    try testing.expect(s.ensure(64, 3));
    try testing.expectEqualStrings("abc", s.slice()[0..3]);

    // Drained to what fits in the initial size: back to it, bytes kept.
    s.shrink(3);
    try testing.expectEqual(@as(usize, 8), s.slice().len);
    try testing.expectEqualStrings("abc", s.slice()[0..3]);
    // More than that still held: kept as it is.
    try testing.expect(s.ensure(20, 3));
    s.shrink(9);
    try testing.expectEqual(@as(usize, 20), s.slice().len);
}

test "ByteStore: without an allocator a growing store holds nothing" {
    var s = ByteStore(64, true, 8){};
    try testing.expect(!s.ensure(1, 0));
    try testing.expectEqual(@as(usize, 0), s.slice().len);
}

test "ByteStore: a refused allocation leaves what was held" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
    var s = ByteStore(64, true, 8){ .allocator = failing.allocator() };
    defer s.release();
    try testing.expect(s.ensure(4, 0));
    @memcpy(s.slice()[0..4], "wxyz");
    try testing.expect(!s.ensure(20, 4));
    try testing.expectEqualStrings("wxyz", s.slice()[0..4]);
}

test "Budget: no more than the limit at once, and what is given back is room again" {
    var budget = Budget{ .parent = testing.allocator, .limit = 100 };
    const a = budget.allocator();
    var s1 = ByteStore(64, true, 8){ .allocator = a };
    defer s1.release();
    var s2 = ByteStore(64, true, 8){ .allocator = a };
    defer s2.release();

    try testing.expect(s1.ensure(64, 0));
    try testing.expectEqual(@as(usize, 64), budget.used);
    // 64 more would be 128: refused, and what s2 held (nothing) stays.
    try testing.expect(!s2.ensure(64, 0));
    try testing.expectEqual(@as(usize, 0), s2.slice().len);
    try testing.expect(s2.ensure(30, 0));
    try testing.expectEqual(@as(usize, 94), budget.used);

    s1.shrink(0);
    try testing.expectEqual(@as(usize, 8 + 30), budget.used);
    try testing.expect(s2.ensure(60, 30));
    s1.release();
    s2.release();
    try testing.expectEqual(@as(usize, 0), budget.used);
}

test "Budget: no limit is no limit" {
    var budget = Budget{ .parent = testing.allocator };
    var s = ByteStore(1 << 20, true, 8){ .allocator = budget.allocator() };
    defer s.release();
    try testing.expect(s.ensure(1 << 20, 0));
}

test "Budget: near the limit, a store grows to what it needs and shrinks where it is" {
    // A parent that resizes its last allocation in place, as a real one
    // often can: the budget alone decides what is refused.
    var backing: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&backing);
    var budget = Budget{ .parent = fba.allocator(), .limit = 30 };
    var s = ByteStore(64, true, 8){ .allocator = budget.allocator() };

    try testing.expect(s.ensure(16, 0));
    @memcpy(s.slice()[0..3], "abc");
    // Doubling to 32 is past 30; 17 is not.
    try testing.expect(s.ensure(17, 3));
    try testing.expectEqual(@as(usize, 17), s.slice().len);
    try testing.expectEqualStrings("abc", s.slice()[0..3]);

    // Full to the limit, with something kept: a new small run would not
    // fit beside the old one, so it shrinks in place.
    try testing.expect(s.ensure(30, 3));
    try testing.expectEqual(@as(usize, 30), budget.used);
    s.shrink(3);
    try testing.expectEqual(@as(usize, 8), s.slice().len);
    try testing.expectEqual(@as(usize, 8), budget.used);
    try testing.expectEqualStrings("abc", s.slice()[0..3]);
    s.release();
    try testing.expectEqual(@as(usize, 0), budget.used);
}
