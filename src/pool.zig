// Fixed-size buffer pool for zero-allocation packet processing.
//
// Pre-allocates a fixed number of packet buffers at init time.
// Acquire/release operations are O(1) via a free list.
// Used for the hot path: no heap allocation during packet processing.

const std = @import("std");
const packet_buf = @import("packet_buf.zig");
const PacketBuf = packet_buf.PacketBuf;

/// A pool of fixed-size buffers.
/// Comptime parameter `capacity` determines the max number of concurrent buffers.
pub fn Pool(comptime capacity: usize, comptime buf_size: usize) type {
    return struct {
        const Self = @This();

        /// Backing storage for all buffers.
        storage: [capacity][buf_size]u8,

        /// Free list (indices into storage). Stack-based: push/pop from top.
        free_list: [capacity]u16,

        /// Number of free buffers.
        free_count: usize,

        /// Initialize the pool with all buffers available.
        pub fn init() Self {
            var self: Self = undefined;
            for (0..capacity) |i| {
                self.free_list[i] = @intCast(i);
            }
            self.free_count = capacity;
            return self;
        }

        /// Acquire a buffer from the pool.
        /// Returns null if the pool is exhausted.
        pub fn acquire(self: *Self) ?BufHandle {
            if (self.free_count == 0) return null;
            self.free_count -= 1;
            const idx = self.free_list[self.free_count];
            return BufHandle{
                .index = idx,
                .pb = PacketBuf.init(&self.storage[idx], packet_buf.max_headroom),
            };
        }

        /// Release a buffer back to the pool.
        pub fn release(self: *Self, handle: *BufHandle) void {
            // Clear data
            handle.pb.reset(packet_buf.max_headroom);
            self.free_list[self.free_count] = handle.index;
            self.free_count += 1;
        }

        /// Number of available (free) buffers.
        pub fn available(self: *const Self) usize {
            return self.free_count;
        }

        /// Number of buffers currently in use.
        pub fn inUse(self: *const Self) usize {
            return capacity - self.free_count;
        }

        /// Handle to an acquired buffer.
        pub const BufHandle = struct {
            index: u16,
            pb: PacketBuf,
        };
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Pool: acquire and release" {
    var p = Pool(4, 256).init();
    try testing.expectEqual(@as(usize, 4), p.available());

    var h1 = p.acquire() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 3), p.available());
    try testing.expectEqual(@as(usize, 1), p.inUse());

    var h2 = p.acquire() orelse return error.TestUnexpectedResult;
    _ = p.acquire() orelse return error.TestUnexpectedResult;
    _ = p.acquire() orelse return error.TestUnexpectedResult;

    // Pool exhausted
    try testing.expectEqual(@as(?Pool(4, 256).BufHandle, null), p.acquire());
    try testing.expectEqual(@as(usize, 0), p.available());

    // Release one
    p.release(&h1);
    try testing.expectEqual(@as(usize, 1), p.available());

    // Can acquire again
    _ = p.acquire() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 0), p.available());

    p.release(&h2);
    try testing.expectEqual(@as(usize, 1), p.available());
}

test "Pool: packet buf operations on acquired buffer" {
    var p = Pool(2, packet_buf.default_capacity).init();
    var handle = p.acquire() orelse return error.TestUnexpectedResult;

    // Use the PacketBuf
    try handle.pb.appendSlice("test payload");
    try testing.expectEqualSlices(u8, "test payload", handle.pb.data());
    try testing.expectEqual(packet_buf.max_headroom, handle.pb.headroom());

    // Push a header
    const hdr = try handle.pb.push(20);
    _ = hdr;
    try testing.expectEqual(@as(usize, 32), handle.pb.len()); // 20 + 12

    p.release(&handle);
}
