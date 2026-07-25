// Zero-copy Buffer Architecture — Reference-counted buffers + scatter-gather I/O.
//
// Sans-IO: no allocations, comptime-sized pools. Enables direct payload
// hand-off between layers without intermediate copies.
//
// Components:
// - RefBuf: reference-counted buffer with atomic-free single-threaded refcount
// - BufView: immutable view into a RefBuf region (no copy)
// - IoVec: scatter-gather descriptor (up to N non-contiguous segments)
// - RefPool: pool of RefBufs with automatic reclaim on refcount→0
//
// Usage pattern:
//   1. Receive path: pool.acquire() → RefBuf, inject raw packet
//   2. Parse: create BufViews pointing to IP header, TCP header, payload
//   3. Hand to transport: transport layer holds BufView of payload (no copy)
//   4. Application reads: returns BufView slice (zero-copy to app)
//   5. When all BufViews are released, RefBuf returns to pool automatically
//
// Send path:
//   1. Application provides payload slice
//   2. IoVec chains: [TCP header segment] + [payload segment] (scatter)
//   3. Link layer iterates IoVec to emit contiguous frame (single memcpy at boundary)

const std = @import("std");

/// Maximum number of scatter-gather segments per IoVec.
pub const max_iov_segments: usize = 8;

/// Buffer size for RefBuf (aligned to MTU + headroom).
pub const ref_buf_size: usize = 2048;

/// Reference-counted buffer.
/// Single-threaded refcount (no atomics needed for sans-IO event loop).
/// When refcount reaches 0, the buffer is eligible for reclaim by the pool.
pub const RefBuf = struct {
    storage: [ref_buf_size]u8 = undefined,
    /// Active reference count. Starts at 1 on acquire.
    ref_count: u16 = 0,
    /// Data region within storage.
    data_start: u16 = 0,
    data_end: u16 = 0,
    /// Pool index (for return-to-pool on release).
    pool_idx: u16 = 0,
    /// Whether this buffer is currently allocated.
    active: bool = false,

    pub fn data(self: *const RefBuf) []const u8 {
        return self.storage[self.data_start..self.data_end];
    }

    pub fn dataMut(self: *RefBuf) []u8 {
        return self.storage[self.data_start..self.data_end];
    }

    pub fn len(self: *const RefBuf) u16 {
        return self.data_end - self.data_start;
    }

    pub fn setRegion(self: *RefBuf, start: u16, end: u16) void {
        self.data_start = start;
        self.data_end = end;
    }

    pub fn copyIn(self: *RefBuf, offset: u16, src: []const u8) bool {
        const end: usize = @as(usize, offset) + src.len;
        if (end > ref_buf_size) return false;
        @memcpy(self.storage[offset..][0..src.len], src);
        return true;
    }
};

/// Immutable view into a portion of a RefBuf.
/// Holding a BufView keeps the underlying RefBuf alive (increments refcount).
/// Must call release() when done.
pub const BufView = struct {
    buf_pool_idx: u16,
    offset: u16,
    length: u16,

    pub fn init(pool_idx: u16, offset: u16, length: u16) BufView {
        return .{
            .buf_pool_idx = pool_idx,
            .offset = offset,
            .length = length,
        };
    }

    pub fn empty() BufView {
        return .{ .buf_pool_idx = 0, .offset = 0, .length = 0 };
    }

    pub fn isEmpty(self: *const BufView) bool {
        return self.length == 0;
    }

    /// Create a sub-view (narrower slice of same underlying buffer).
    pub fn subView(self: *const BufView, rel_offset: u16, sub_len: u16) ?BufView {
        const rel_end: u32 = @as(u32, rel_offset) + @as(u32, sub_len);
        if (rel_end > self.length) return null;
        const new_offset: u32 = @as(u32, self.offset) + @as(u32, rel_offset);
        if (new_offset + sub_len > ref_buf_size) return null;
        return BufView{
            .buf_pool_idx = self.buf_pool_idx,
            .offset = @intCast(new_offset),
            .length = sub_len,
        };
    }
};

/// Scatter-gather I/O vector.
/// Describes a logical packet as up to `max_iov_segments` non-contiguous memory regions.
/// Used on the send path to avoid copying headers into the payload buffer.
pub const IoVec = struct {
    segments: [max_iov_segments]Segment = [_]Segment{.{}} ** max_iov_segments,
    count: u8 = 0,

    pub const Segment = struct {
        ptr: [*]const u8 = undefined,
        len: u16 = 0,

        pub fn slice(self: *const Segment) []const u8 {
            return self.ptr[0..self.len];
        }
    };

    pub fn init() IoVec {
        return .{};
    }

    /// Add a segment to the IoVec.
    pub fn push(self: *IoVec, data: []const u8) bool {
        if (self.count >= max_iov_segments) return false;
        self.segments[self.count] = .{
            .ptr = data.ptr,
            .len = @intCast(data.len),
        };
        self.count += 1;
        return true;
    }

    /// Total bytes across all segments.
    pub fn totalLen(self: *const IoVec) usize {
        var total: usize = 0;
        for (self.segments[0..self.count]) |seg| {
            total += seg.len;
        }
        return total;
    }

    /// Flatten (gather) all segments into a contiguous buffer.
    /// Returns number of bytes written, or null if buffer too small.
    pub fn flatten(self: *const IoVec, out: []u8) ?usize {
        const needed = self.totalLen();
        if (out.len < needed) return null;
        var offset: usize = 0;
        for (self.segments[0..self.count]) |seg| {
            @memcpy(out[offset .. offset + seg.len], seg.slice());
            offset += seg.len;
        }
        return offset;
    }

    /// Iterate over segments.
    pub fn iterator(self: *const IoVec) Iterator {
        return .{ .iov = self, .idx = 0 };
    }

    pub const Iterator = struct {
        iov: *const IoVec,
        idx: u8,

        pub fn next(self: *Iterator) ?[]const u8 {
            if (self.idx >= self.iov.count) return null;
            const seg = &self.iov.segments[self.idx];
            self.idx += 1;
            return seg.slice();
        }
    };
};

/// Pool of reference-counted buffers.
/// Tracks refcounts and automatically reclaims buffers when all views are released.
pub fn RefPool(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        bufs: [capacity]RefBuf = [_]RefBuf{.{}} ** capacity,
        /// Free list (stack).
        free_list: [capacity]u16 = undefined,
        free_count: usize = capacity,

        pub fn init() Self {
            var self = Self{};
            for (0..capacity) |i| {
                self.free_list[i] = @intCast(i);
                self.bufs[i].pool_idx = @intCast(i);
            }
            return self;
        }

        /// Acquire a buffer. Returns pool index, or null if exhausted.
        pub fn acquire(self: *Self) ?u16 {
            if (self.free_count == 0) return null;
            self.free_count -= 1;
            const idx = self.free_list[self.free_count];
            self.bufs[idx].active = true;
            self.bufs[idx].ref_count = 1;
            self.bufs[idx].data_start = 0;
            self.bufs[idx].data_end = 0;
            return idx;
        }

        /// Increment reference count on a buffer.
        pub fn retain(self: *Self, idx: u16) void {
            if (idx >= capacity) return;
            if (self.bufs[idx].active) {
                self.bufs[idx].ref_count += 1;
            }
        }

        /// Decrement reference count. Returns true if buffer was freed.
        pub fn release(self: *Self, idx: u16) bool {
            if (idx >= capacity) return false;
            var buf = &self.bufs[idx];
            if (!buf.active) return false;
            if (buf.ref_count == 0) return false;

            buf.ref_count -= 1;
            if (buf.ref_count == 0) {
                buf.active = false;
                self.free_list[self.free_count] = idx;
                self.free_count += 1;
                return true;
            }
            return false;
        }

        /// Get a reference to the buffer at `idx`.
        pub fn get(self: *Self, idx: u16) ?*RefBuf {
            if (idx >= capacity) return null;
            if (!self.bufs[idx].active) return null;
            return &self.bufs[idx];
        }

        pub fn getConst(self: *const Self, idx: u16) ?*const RefBuf {
            if (idx >= capacity) return null;
            if (!self.bufs[idx].active) return null;
            return &self.bufs[idx];
        }

        /// Read the data that a BufView points to.
        pub fn viewData(self: *const Self, view: BufView) ?[]const u8 {
            const buf = self.getConst(view.buf_pool_idx) orelse return null;
            const end: u32 = @as(u32, view.offset) + @as(u32, view.length);
            if (end > ref_buf_size) return null;
            return buf.storage[view.offset..][0..view.length];
        }

        /// Create a BufView for the current data region of a buffer.
        pub fn viewOf(self: *Self, idx: u16) ?BufView {
            const buf = self.get(idx) orelse return null;
            self.retain(idx);
            return BufView.init(idx, buf.data_start, buf.len());
        }

        /// Create a BufView for a sub-region and increment refcount.
        pub fn viewSlice(self: *Self, idx: u16, offset: u16, length: u16) ?BufView {
            if (self.get(idx) == null) return null;
            const end: u32 = @as(u32, offset) + @as(u32, length);
            if (end > ref_buf_size) return null;
            self.retain(idx);
            return BufView.init(idx, offset, length);
        }

        /// Release a BufView (decrements the underlying buffer's refcount).
        pub fn releaseView(self: *Self, view: BufView) void {
            _ = self.release(view.buf_pool_idx);
        }

        /// Number of available buffers.
        pub fn available(self: *const Self) usize {
            return self.free_count;
        }

        /// Number of buffers in use.
        pub fn inUse(self: *const Self) usize {
            return capacity - self.free_count;
        }

        /// Get the refcount for a buffer (for testing/debugging).
        pub fn refCount(self: *const Self, idx: u16) u16 {
            if (idx >= capacity) return 0;
            return self.bufs[idx].ref_count;
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "RefPool: acquire and release" {
    var pool = RefPool(4).init();
    try testing.expectEqual(@as(usize, 4), pool.available());

    const idx = pool.acquire().?;
    try testing.expectEqual(@as(usize, 3), pool.available());
    try testing.expectEqual(@as(u16, 1), pool.refCount(idx));

    _ = pool.release(idx);
    try testing.expectEqual(@as(usize, 4), pool.available());
}

test "RefPool: refcount retain/release" {
    var pool = RefPool(4).init();
    const idx = pool.acquire().?;

    pool.retain(idx);
    try testing.expectEqual(@as(u16, 2), pool.refCount(idx));

    _ = pool.release(idx);
    try testing.expectEqual(@as(u16, 1), pool.refCount(idx));
    try testing.expectEqual(@as(usize, 3), pool.available()); // still in use

    _ = pool.release(idx);
    try testing.expectEqual(@as(u16, 0), pool.refCount(idx));
    try testing.expectEqual(@as(usize, 4), pool.available()); // freed
}

test "RefPool: BufView zero-copy read" {
    var pool = RefPool(4).init();
    const idx = pool.acquire().?;

    // Write data into buffer
    var buf = pool.get(idx).?;
    const payload = "hello zero-copy";
    @memcpy(buf.storage[128 .. 128 + payload.len], payload);
    buf.setRegion(128, 128 + @as(u16, payload.len));

    // Create view
    const view = pool.viewOf(idx).?;
    try testing.expectEqual(@as(u16, 2), pool.refCount(idx)); // original + view

    // Read through view (zero-copy)
    const data = pool.viewData(view).?;
    try testing.expectEqualSlices(u8, payload, data);

    // Release view
    pool.releaseView(view);
    try testing.expectEqual(@as(u16, 1), pool.refCount(idx));

    // Release original
    _ = pool.release(idx);
    try testing.expectEqual(@as(usize, 4), pool.available());
}

test "RefPool: sub-view" {
    var pool = RefPool(4).init();
    const idx = pool.acquire().?;

    var buf = pool.get(idx).?;
    const packet = "IP-HDR|TCP-HDR|PAYLOAD-DATA";
    @memcpy(buf.storage[0..packet.len], packet);
    buf.setRegion(0, @intCast(packet.len));

    // Full view
    const full = pool.viewOf(idx).?;

    // Sub-view: TCP header (offset 7, len 7)
    const tcp_view = full.subView(7, 7).?;
    const tcp_data = pool.viewData(tcp_view).?;
    try testing.expectEqualSlices(u8, "TCP-HDR", tcp_data);

    // Sub-view: payload (offset 15, len 12)
    const payload_view = full.subView(15, 12).?;
    const payload_data = pool.viewData(payload_view).?;
    try testing.expectEqualSlices(u8, "PAYLOAD-DATA", payload_data);

    // Sub-views don't add refcount (they're just offset+len structs)
    // Only viewOf/viewSlice add refcount
    pool.releaseView(full);
    _ = pool.release(idx);
    try testing.expectEqual(@as(usize, 4), pool.available());
}

test "RefPool: pool exhaustion" {
    var pool = RefPool(2).init();
    const a = pool.acquire().?;
    const b = pool.acquire().?;
    try testing.expect(pool.acquire() == null);

    _ = pool.release(a);
    try testing.expectEqual(@as(usize, 1), pool.available());
    const c = pool.acquire().?;
    try testing.expect(pool.acquire() == null);

    _ = pool.release(b);
    _ = pool.release(c);
    try testing.expectEqual(@as(usize, 2), pool.available());
}

test "RefPool: multiple views same buffer" {
    var pool = RefPool(4).init();
    const idx = pool.acquire().?;
    try testing.expectEqual(@as(u16, 1), pool.refCount(idx));

    // Create multiple views
    const v1 = pool.viewSlice(idx, 0, 100).?;
    const v2 = pool.viewSlice(idx, 100, 200).?;
    const v3 = pool.viewSlice(idx, 300, 50).?;
    try testing.expectEqual(@as(u16, 4), pool.refCount(idx)); // 1 + 3 views

    // Release views one by one
    pool.releaseView(v1);
    try testing.expectEqual(@as(u16, 3), pool.refCount(idx));
    pool.releaseView(v2);
    try testing.expectEqual(@as(u16, 2), pool.refCount(idx));
    pool.releaseView(v3);
    try testing.expectEqual(@as(u16, 1), pool.refCount(idx));

    // Final release frees
    _ = pool.release(idx);
    try testing.expectEqual(@as(usize, 4), pool.available());
}

test "RefBuf: copyIn" {
    var pool = RefPool(4).init();
    const idx = pool.acquire().?;
    var buf = pool.get(idx).?;

    try testing.expect(buf.copyIn(0, "test"));
    try testing.expectEqualSlices(u8, "test", buf.storage[0..4]);

    // Over-size fails
    var large: [ref_buf_size + 1]u8 = undefined;
    try testing.expect(!buf.copyIn(0, &large));

    _ = pool.release(idx);
}

test "IoVec: scatter-gather" {
    var iov = IoVec.init();

    const hdr = "HEADER:";
    const payload = "the payload data";
    const trailer = ":END";

    try testing.expect(iov.push(hdr));
    try testing.expect(iov.push(payload));
    try testing.expect(iov.push(trailer));

    try testing.expectEqual(@as(u8, 3), iov.count);
    try testing.expectEqual(hdr.len + payload.len + trailer.len, iov.totalLen());

    // Flatten (gather)
    var out: [128]u8 = undefined;
    const n = iov.flatten(&out).?;
    try testing.expectEqual(hdr.len + payload.len + trailer.len, n);
    try testing.expectEqualSlices(u8, "HEADER:the payload data:END", out[0..n]);
}

test "IoVec: flatten into too-small buffer" {
    var iov = IoVec.init();
    _ = iov.push("long data that won't fit");

    var tiny: [4]u8 = undefined;
    try testing.expect(iov.flatten(&tiny) == null);
}

test "IoVec: max segments" {
    var iov = IoVec.init();
    var i: u8 = 0;
    while (i < max_iov_segments) : (i += 1) {
        try testing.expect(iov.push("x"));
    }
    // Full
    try testing.expect(!iov.push("overflow"));
    try testing.expectEqual(@as(u8, max_iov_segments), iov.count);
}

test "IoVec: iterator" {
    var iov = IoVec.init();
    _ = iov.push("aaa");
    _ = iov.push("bb");
    _ = iov.push("c");

    var iter = iov.iterator();
    try testing.expectEqualSlices(u8, "aaa", iter.next().?);
    try testing.expectEqualSlices(u8, "bb", iter.next().?);
    try testing.expectEqualSlices(u8, "c", iter.next().?);
    try testing.expect(iter.next() == null);
}

test "BufView: subView boundary check" {
    const view = BufView.init(0, 10, 20); // offset=10, length=20

    // Valid sub-view
    const sub = view.subView(5, 10).?;
    try testing.expectEqual(@as(u16, 15), sub.offset); // 10 + 5
    try testing.expectEqual(@as(u16, 10), sub.length);

    // Out-of-bounds sub-view
    try testing.expect(view.subView(15, 10) == null); // 15+10 > 20
}

test "RefPool: release inactive buffer is no-op" {
    var pool = RefPool(4).init();
    // Release a buffer that was never acquired
    try testing.expect(!pool.release(0));
    try testing.expectEqual(@as(usize, 4), pool.available());
}

test "RefPool: viewData on released buffer returns null" {
    var pool = RefPool(4).init();
    const idx = pool.acquire().?;
    const view = pool.viewOf(idx).?;

    // Release both refs
    pool.releaseView(view);
    _ = pool.release(idx);

    // Buffer is now inactive — viewData should return null
    try testing.expect(pool.viewData(view) == null);
}
