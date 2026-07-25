// Raw IP Socket Endpoint.
//
// Allows sending/receiving raw IP packets for custom protocols (e.g., OSPF, GRE).
// Binds to an IP protocol number and receives full IP payload for matched packets.
//
// Sans-IO: buffers received payloads; caller polls and sends via link.

const std = @import("std");

/// Maximum number of raw endpoints.
pub const max_endpoints: usize = 16;

/// Maximum receive buffer per endpoint.
const max_recv_buf: usize = 4096;

/// Maximum queued datagrams.
const max_queue: usize = 16;

/// A received raw datagram.
pub const RawDatagram = struct {
    src_addr: [4]u8 = .{0} ** 4,
    dst_addr: [4]u8 = .{0} ** 4,
    data: [1500]u8 = undefined,
    len: usize = 0,
};

/// Raw IP endpoint — binds to a protocol number.
pub const Endpoint = struct {
    protocol: u8 = 0,
    active: bool = false,
    recv_queue: [max_queue]RawDatagram = [_]RawDatagram{.{}} ** max_queue,
    recv_head: usize = 0,
    recv_tail: usize = 0,
    recv_count: usize = 0,

    pub fn init(protocol: u8) Endpoint {
        return .{ .protocol = protocol, .active = true };
    }

    /// Deliver an inbound IP payload to this endpoint.
    /// Returns true if queued, false if queue full.
    pub fn deliver(self: *Endpoint, src_addr: [4]u8, dst_addr: [4]u8, payload: []const u8) bool {
        if (self.recv_count >= max_queue) return false;
        if (payload.len > 1500) return false;

        var dgram = &self.recv_queue[self.recv_tail];
        dgram.src_addr = src_addr;
        dgram.dst_addr = dst_addr;
        @memcpy(dgram.data[0..payload.len], payload);
        dgram.len = payload.len;

        self.recv_tail = (self.recv_tail + 1) % max_queue;
        self.recv_count += 1;
        return true;
    }

    /// Read the next received datagram. Returns null if queue empty.
    pub fn recv(self: *Endpoint) ?*const RawDatagram {
        if (self.recv_count == 0) return null;
        const dgram = &self.recv_queue[self.recv_head];
        self.recv_head = (self.recv_head + 1) % max_queue;
        self.recv_count -= 1;
        return dgram;
    }

    /// Check if there's data available.
    pub fn hasData(self: *const Endpoint) bool {
        return self.recv_count > 0;
    }

    /// Close the endpoint.
    pub fn close(self: *Endpoint) void {
        self.active = false;
        self.recv_count = 0;
        self.recv_head = 0;
        self.recv_tail = 0;
    }
};

/// Raw endpoint manager — demuxes by protocol number.
pub const RawManager = struct {
    endpoints: [max_endpoints]Endpoint = [_]Endpoint{.{}} ** max_endpoints,
    count: usize = 0,

    pub fn init() RawManager {
        return .{};
    }

    /// Bind a new raw endpoint to a protocol number.
    /// Returns the endpoint index, or null if full.
    pub fn bind(self: *RawManager, protocol: u8) ?usize {
        for (&self.endpoints, 0..) |*ep, i| {
            if (!ep.active) {
                ep.* = Endpoint.init(protocol);
                self.count += 1;
                return i;
            }
        }
        return null;
    }

    /// Unbind an endpoint.
    pub fn unbind(self: *RawManager, idx: usize) void {
        if (idx >= max_endpoints) return;
        if (self.endpoints[idx].active) {
            self.endpoints[idx].close();
            self.count -= 1;
        }
    }

    /// Deliver an inbound IP packet to matching raw endpoints.
    /// `protocol` is the IP protocol number from the IP header.
    /// Returns true if at least one endpoint received the data.
    pub fn deliver(self: *RawManager, protocol: u8, src_addr: [4]u8, dst_addr: [4]u8, payload: []const u8) bool {
        var delivered = false;
        for (&self.endpoints) |*ep| {
            if (ep.active and ep.protocol == protocol) {
                if (ep.deliver(src_addr, dst_addr, payload)) {
                    delivered = true;
                }
            }
        }
        return delivered;
    }

    /// Get endpoint reference.
    pub fn getEndpoint(self: *RawManager, idx: usize) ?*Endpoint {
        if (idx >= max_endpoints) return null;
        if (!self.endpoints[idx].active) return null;
        return &self.endpoints[idx];
    }
};

/// Outbound raw packet descriptor (for building IP packets).
pub const RawSendDesc = struct {
    protocol: u8,
    src_addr: [4]u8,
    dst_addr: [4]u8,
    payload: []const u8,
    ttl: u8 = 64,
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "RawManager: bind and deliver" {
    var mgr = RawManager.init();

    // Bind to OSPF (protocol 89)
    const idx = mgr.bind(89).?;
    try testing.expectEqual(@as(usize, 0), idx);
    try testing.expectEqual(@as(usize, 1), mgr.count);

    // Deliver a packet
    const payload = "hello raw";
    const delivered = mgr.deliver(89, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, payload);
    try testing.expect(delivered);

    // Read it back
    const ep = mgr.getEndpoint(idx).?;
    const dgram = ep.recv().?;
    try testing.expectEqual(@as(usize, payload.len), dgram.len);
    try testing.expectEqualSlices(u8, payload, dgram.data[0..dgram.len]);
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 1 }, &dgram.src_addr);
}

test "RawManager: wrong protocol not delivered" {
    var mgr = RawManager.init();
    _ = mgr.bind(89); // OSPF

    // Deliver GRE (47) — should not match
    const delivered = mgr.deliver(47, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "gre data");
    try testing.expect(!delivered);
}

test "RawManager: multiple endpoints same protocol" {
    var mgr = RawManager.init();
    const idx1 = mgr.bind(47).?;
    const idx2 = mgr.bind(47).?;

    const delivered = mgr.deliver(47, .{ 1, 2, 3, 4 }, .{ 5, 6, 7, 8 }, "multi");
    try testing.expect(delivered);

    // Both should have received it
    const ep1 = mgr.getEndpoint(idx1).?;
    const ep2 = mgr.getEndpoint(idx2).?;
    try testing.expect(ep1.hasData());
    try testing.expect(ep2.hasData());
}

test "RawManager: unbind" {
    var mgr = RawManager.init();
    const idx = mgr.bind(89).?;
    try testing.expectEqual(@as(usize, 1), mgr.count);

    mgr.unbind(idx);
    try testing.expectEqual(@as(usize, 0), mgr.count);

    // Should no longer deliver
    const delivered = mgr.deliver(89, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "gone");
    try testing.expect(!delivered);
}

test "Endpoint: queue overflow" {
    var ep = Endpoint.init(89);
    var i: usize = 0;
    while (i < max_queue) : (i += 1) {
        try testing.expect(ep.deliver(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "x"));
    }
    // Queue full
    try testing.expect(!ep.deliver(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "overflow"));

    // Drain one → can deliver again
    _ = ep.recv();
    try testing.expect(ep.deliver(.{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, "y"));
}
