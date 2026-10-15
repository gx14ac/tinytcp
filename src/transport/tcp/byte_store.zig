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
        /// little at a time does not copy everything each time.
        pub fn ensure(self: *Self, need: usize, keep: usize) bool {
            if (!grow) return need <= max;
            if (need <= self.heap.len) return true;
            if (need > max) return false;
            const a = self.allocator orelse return false;
            const want = @min(max, @max(need, @max(self.heap.len * 2, initial_len)));
            const fresh = a.alloc(u8, want) catch return false;
            const kept = @min(keep, self.heap.len);
            @memcpy(fresh[0..kept], self.heap[0..kept]);
            if (self.heap.len > 0) a.free(self.heap);
            self.heap = fresh;
            return true;
        }

        /// Give back what is past `initial_len` once the first `keep`
        /// bytes fit in it: a connection that has drained goes back to
        /// costing little. Kept at `initial_len` rather than nothing, so a
        /// connection trading small requests does not allocate for each.
        pub fn shrink(self: *Self, keep: usize) void {
            if (!grow) return;
            if (self.heap.len <= initial_len or keep > initial_len) return;
            const a = self.allocator orelse return;
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
