// UDP Endpoint: connectionless datagram send/receive.
//
// Sans-IO: caller injects received datagrams and polls for outbound.
// Supports bind (local port), connect (remote addr/port), send, recv.

const std = @import("std");
const udp_header = @import("../../header/udp.zig");
const checksum_mod = @import("../../checksum.zig");

/// Maximum number of datagrams buffered for receive.
const max_rx_queue: usize = 64;

/// Maximum datagram payload size.
const max_dgram_size: usize = 1472; // 1500 - 20 (IP) - 8 (UDP)

/// A received datagram.
pub const Datagram = struct {
    src_addr: [4]u8 = .{ 0, 0, 0, 0 },
    src_port: u16 = 0,
    data: [max_dgram_size]u8 = undefined,
    len: u16 = 0,
};

/// Outbound datagram request.
pub const SendRequest = struct {
    dst_addr: [4]u8,
    dst_port: u16,
    data_offset: usize,
    data_len: usize,
};

/// UDP Endpoint state.
pub const Endpoint = struct {
    // Binding
    local_port: u16 = 0,
    bound: bool = false,

    // Connected remote (optional)
    remote_addr: [4]u8 = .{ 0, 0, 0, 0 },
    remote_port: u16 = 0,
    connected: bool = false,

    // Receive queue (ring buffer)
    rx_queue: [max_rx_queue]Datagram = undefined,
    rx_head: usize = 0,
    rx_tail: usize = 0,
    rx_count: usize = 0,

    // Send buffer (single pending datagram for poll-based send)
    tx_buf: [max_dgram_size]u8 = undefined,
    tx_len: usize = 0,
    tx_dst_addr: [4]u8 = .{ 0, 0, 0, 0 },
    tx_dst_port: u16 = 0,
    tx_pending: bool = false,

    /// Bind to a local port.
    pub fn bind(self: *Endpoint, port: u16) void {
        self.local_port = port;
        self.bound = true;
    }

    /// Connect to a remote address (sets default destination).
    pub fn connectTo(self: *Endpoint, addr: [4]u8, port: u16) void {
        self.remote_addr = addr;
        self.remote_port = port;
        self.connected = true;
    }

    /// Queue a datagram for sending to a specific destination.
    /// Returns true if accepted, false if send buffer is full.
    pub fn sendTo(self: *Endpoint, dst_addr: [4]u8, dst_port: u16, data: []const u8) bool {
        if (self.tx_pending) return false;
        const copy_len = @min(data.len, max_dgram_size);
        @memcpy(self.tx_buf[0..copy_len], data[0..copy_len]);
        self.tx_len = copy_len;
        self.tx_dst_addr = dst_addr;
        self.tx_dst_port = dst_port;
        self.tx_pending = true;
        return true;
    }

    /// Queue a datagram for sending to the connected remote.
    /// Returns true if accepted.
    pub fn send(self: *Endpoint, data: []const u8) bool {
        if (!self.connected) return false;
        return self.sendTo(self.remote_addr, self.remote_port, data);
    }

    /// Receive a datagram. Returns null if queue is empty.
    pub fn recv(self: *Endpoint) ?Datagram {
        if (self.rx_count == 0) return null;
        const dgram = self.rx_queue[self.rx_head];
        self.rx_head = (self.rx_head + 1) % max_rx_queue;
        self.rx_count -= 1;
        return dgram;
    }

    /// Check if there's a pending outbound datagram.
    pub fn hasPending(self: *const Endpoint) bool {
        return self.tx_pending;
    }

    /// Consume the pending outbound datagram (called by stack after building packet).
    pub fn consumePending(self: *Endpoint) ?SendRequest {
        if (!self.tx_pending) return null;
        self.tx_pending = false;
        return SendRequest{
            .dst_addr = self.tx_dst_addr,
            .dst_port = self.tx_dst_port,
            .data_offset = 0,
            .data_len = self.tx_len,
        };
    }

    /// Get the pending send data slice.
    pub fn pendingData(self: *const Endpoint) []const u8 {
        return self.tx_buf[0..self.tx_len];
    }

    /// Deliver an incoming UDP datagram to this endpoint.
    /// Called by the stack after demuxing.
    pub fn deliver(self: *Endpoint, src_addr: [4]u8, src_port: u16, payload: []const u8) void {
        // If connected, filter by remote
        if (self.connected) {
            if (!std.mem.eql(u8, &src_addr, &self.remote_addr) or src_port != self.remote_port) {
                return;
            }
        }

        if (self.rx_count >= max_rx_queue) return; // drop if full

        var dgram = Datagram{
            .src_addr = src_addr,
            .src_port = src_port,
        };
        const copy_len = @min(payload.len, max_dgram_size);
        @memcpy(dgram.data[0..copy_len], payload[0..copy_len]);
        dgram.len = @intCast(copy_len);

        self.rx_queue[self.rx_tail] = dgram;
        self.rx_tail = (self.rx_tail + 1) % max_rx_queue;
        self.rx_count += 1;
    }

    /// Number of datagrams available to read.
    pub fn available(self: *const Endpoint) usize {
        return self.rx_count;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "UDP Endpoint: bind and recv" {
    var ep = Endpoint{};
    ep.bind(5000);
    try testing.expect(ep.bound);
    try testing.expectEqual(@as(u16, 5000), ep.local_port);

    // Deliver a datagram
    ep.deliver(.{ 10, 0, 0, 1 }, 1234, "hello udp");

    // Receive it
    const dgram = ep.recv() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, &dgram.src_addr);
    try testing.expectEqual(@as(u16, 1234), dgram.src_port);
    try testing.expectEqualSlices(u8, "hello udp", dgram.data[0..dgram.len]);
}

test "UDP Endpoint: send" {
    var ep = Endpoint{};
    ep.bind(5000);
    ep.connectTo(.{ 10, 0, 0, 2 }, 8080);

    const ok = ep.send("response");
    try testing.expect(ok);
    try testing.expect(ep.hasPending());

    const req = ep.consumePending() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, &req.dst_addr);
    try testing.expectEqual(@as(u16, 8080), req.dst_port);
    try testing.expectEqual(@as(usize, 8), req.data_len);
}

test "UDP Endpoint: sendTo" {
    var ep = Endpoint{};
    ep.bind(5000);

    const ok = ep.sendTo(.{ 192, 168, 1, 1 }, 53, "dns query");
    try testing.expect(ok);

    const data = ep.pendingData();
    try testing.expectEqualSlices(u8, "dns query", data);
}

test "UDP Endpoint: connected filter" {
    var ep = Endpoint{};
    ep.bind(5000);
    ep.connectTo(.{ 10, 0, 0, 1 }, 8080);

    // Deliver from connected remote — accepted
    ep.deliver(.{ 10, 0, 0, 1 }, 8080, "ok");
    try testing.expectEqual(@as(usize, 1), ep.available());

    // Deliver from different source — dropped
    ep.deliver(.{ 10, 0, 0, 2 }, 8080, "dropped");
    try testing.expectEqual(@as(usize, 1), ep.available());
}

test "UDP Endpoint: rx queue overflow drops" {
    var ep = Endpoint{};
    ep.bind(5000);

    // Fill the queue
    var i: usize = 0;
    while (i < max_rx_queue) : (i += 1) {
        ep.deliver(.{ 10, 0, 0, 1 }, 1234, "x");
    }
    try testing.expectEqual(max_rx_queue, ep.available());

    // One more should be dropped
    ep.deliver(.{ 10, 0, 0, 1 }, 1234, "dropped");
    try testing.expectEqual(max_rx_queue, ep.available());
}
