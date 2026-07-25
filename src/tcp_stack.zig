// TcpStack: integrates TCP Connection management with the Stack.
//
// Manages a pool of TCP connections, dispatches inbound segments,
// and drives the Forwarder pattern (accept all SYNs, proxy to external).
//
// Sans-IO: produces outbound packets and forward requests for the caller.

const std = @import("std");
const header = @import("header.zig");
const packet_buf = @import("packet_buf.zig");
const PacketBuf = packet_buf.PacketBuf;
const checksum_mod = @import("checksum.zig");
const tcp_connection = @import("transport/tcp/connection.zig");
const Connection = tcp_connection.Connection;
const ConnState = tcp_connection.State;
const ConnOutput = tcp_connection.Output;

/// TCP connection identifier.
pub const ConnId = struct {
    local_addr: [4]u8 = .{ 0, 0, 0, 0 },
    local_port: u16 = 0,
    remote_addr: [4]u8 = .{ 0, 0, 0, 0 },
    remote_port: u16 = 0,

    pub fn eql(a: ConnId, b: ConnId) bool {
        return std.mem.eql(u8, &a.local_addr, &b.local_addr) and
            a.local_port == b.local_port and
            std.mem.eql(u8, &a.remote_addr, &b.remote_addr) and
            a.remote_port == b.remote_port;
    }
};

/// Event emitted by the TcpStack for the caller to act on.
pub const Event = union(enum) {
    /// A new TCP connection was accepted (SYN received, SYN+ACK sent).
    /// Caller should open an OS socket to the real destination.
    accepted: struct {
        conn_idx: u16,
        id: ConnId,
    },
    /// A connection has data available for reading.
    data_available: u16,
    /// A connection was closed.
    closed: u16,
    /// An outbound packet is ready (already in the link endpoint).
    packet_sent,
    /// Nothing happened.
    none,
};

/// TCP stack managing a pool of connections.
pub fn TcpStack(comptime max_conns: usize) type {
    return struct {
        const Self = @This();

        const ConnSlot = struct {
            conn: Connection = .{},
            id: ConnId = .{},
            active: bool = false,
        };

        conns: [max_conns]ConnSlot = [_]ConnSlot{.{}} ** max_conns,
        active_count: usize = 0,
        /// ISN counter (simple increment; production would use ChaCha)
        isn_counter: u32 = 100000,
        /// Local addresses this stack answers for
        local_addrs: [4][4]u8 = [_][4]u8{.{ 0, 0, 0, 0 }} ** 4,
        local_addr_count: u8 = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn addLocalAddr(self: *Self, addr: [4]u8) void {
            if (self.local_addr_count < 4) {
                self.local_addrs[self.local_addr_count] = addr;
                self.local_addr_count += 1;
            }
        }

        /// Handle an inbound TCP segment. Returns an event.
        pub fn handleSegment(
            self: *Self,
            now_ms: u64,
            src_addr: [4]u8,
            src_port: u16,
            dst_addr: [4]u8,
            dst_port: u16,
            tcp_data: []const u8,
        ) Event {
            const tcp_hdr = header.tcp.Header.parse(tcp_data) catch return .none;
            const flags = tcp_hdr.flags();
            const seg_seq = tcp_hdr.seqNum();
            const seg_ack = tcp_hdr.ackNum();
            const seg_wnd = tcp_hdr.windowSize();
            const hdr_len = tcp_hdr.headerLen();
            const payload = if (tcp_data.len > hdr_len) tcp_data[hdr_len..] else &[_]u8{};

            const id = ConnId{
                .local_addr = dst_addr,
                .local_port = dst_port,
                .remote_addr = src_addr,
                .remote_port = src_port,
            };

            // Find existing connection
            if (self.findConn(id)) |idx| {
                const slot = &self.conns[idx];
                const output = slot.conn.onSegment(now_ms, flags, seg_seq, seg_ack, seg_wnd, payload);
                self.handleOutput(idx, output);

                if (payload.len > 0) {
                    return .{ .data_available = @intCast(idx) };
                }
                if (slot.conn.state == .closed) {
                    slot.active = false;
                    self.active_count -= 1;
                    return .{ .closed = @intCast(idx) };
                }
                return .none;
            }

            // New SYN → accept (Forwarder pattern)
            if (flags.syn and !flags.ack) {
                return self.acceptNewConn(now_ms, id, seg_seq, seg_wnd);
            }

            return .none;
        }

        /// Accept a new inbound TCP connection.
        fn acceptNewConn(self: *Self, now_ms: u64, id: ConnId, peer_seq: u32, peer_wnd: u16) Event {
            const idx = self.allocSlot() orelse return .none;
            const isn = self.nextIsn();

            var slot = &self.conns[idx];
            slot.id = id;
            slot.active = true;
            slot.conn = Connection.listen(id.local_port);
            slot.conn.sender = @import("transport/tcp/sender.zig").Sender.init(isn, 1460);

            // Feed the SYN
            _ = slot.conn.onSegment(now_ms, .{ .syn = true }, peer_seq, 0, peer_wnd, &.{});
            self.active_count += 1;

            return .{ .accepted = .{ .conn_idx = @intCast(idx), .id = id } };
        }

        /// Write data to a connection's send buffer.
        pub fn write(self: *Self, conn_idx: u16, data: []const u8) usize {
            if (conn_idx >= max_conns) return 0;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return 0;
            return slot.conn.write(data);
        }

        /// Read data from a connection's receive buffer.
        pub fn read(self: *Self, conn_idx: u16, buf: []u8) usize {
            if (conn_idx >= max_conns) return 0;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return 0;
            return slot.conn.read(buf);
        }

        /// Close a connection.
        pub fn close(self: *Self, conn_idx: u16) void {
            if (conn_idx >= max_conns) return;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return;
            slot.conn.close();
        }

        /// Poll all connections for output (retransmits, delayed ACKs, data).
        /// Call periodically. Returns list of segments to send via buildSegment().
        pub fn poll(self: *Self, now_ms: u64, out_segments: []Segment) usize {
            var count: usize = 0;
            for (&self.conns, 0..) |*slot, idx| {
                if (!slot.active) continue;
                if (count >= out_segments.len) break;

                const output = slot.conn.poll(now_ms);
                switch (output) {
                    .send => |seg| {
                        out_segments[count] = Segment{
                            .conn_idx = @intCast(idx),
                            .id = slot.id,
                            .seg = seg,
                        };
                        count += 1;
                    },
                    .closed => {
                        slot.active = false;
                        self.active_count -= 1;
                    },
                    .aborted => {
                        slot.active = false;
                        self.active_count -= 1;
                    },
                    else => {},
                }
            }
            return count;
        }

        /// Get the connection send buffer for building outbound packets.
        pub fn sendBuf(self: *Self, conn_idx: u16) ?[]const u8 {
            if (conn_idx >= max_conns) return null;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return null;
            return slot.conn.send_buf[0..slot.conn.send_buf_len];
        }

        /// Next time poll() should be called.
        pub fn nextPollAt(self: *const Self) ?u64 {
            var earliest: ?u64 = null;
            for (&self.conns) |*slot| {
                if (!slot.active) continue;
                if (slot.conn.nextPollAt()) |t| {
                    if (earliest == null or t < earliest.?) {
                        earliest = t;
                    }
                }
            }
            return earliest;
        }

        fn findConn(self: *Self, id: ConnId) ?usize {
            for (&self.conns, 0..) |*slot, idx| {
                if (slot.active and slot.id.eql(id)) return idx;
            }
            return null;
        }

        fn allocSlot(self: *const Self) ?usize {
            for (self.conns[0..], 0..) |slot, idx| {
                if (!slot.active) return idx;
            }
            return null;
        }

        fn nextIsn(self: *Self) u32 {
            const isn = self.isn_counter;
            self.isn_counter +%= 64000;
            return isn;
        }

        fn handleOutput(self: *Self, idx: usize, output: ConnOutput) void {
            _ = self;
            _ = idx;
            _ = output;
            // Output handling is deferred to poll() for sans-IO design
        }

        /// Outbound segment descriptor (produced by poll).
        pub const Segment = struct {
            conn_idx: u16 = 0,
            id: ConnId = .{},
            seg: tcp_connection.Segment = .{},
        };
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "TcpStack: accept SYN creates connection" {
    var ts = TcpStack(16).init();
    ts.addLocalAddr(.{ 10, 0, 0, 1 });

    // Build a SYN segment
    var tcp_buf: [20]u8 = undefined;
    var hdr = header.tcp.MutableHeader.init(&tcp_buf) catch unreachable;
    hdr.setSrcPort(5000);
    hdr.setDstPort(80);
    hdr.setSeqNum(1000);
    hdr.setAckNum(0);
    hdr.setFlags(.{ .syn = true });
    hdr.setWindowSize(65535);
    // data offset already set to 5 by init()

    const event = ts.handleSegment(0, .{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, &tcp_buf);
    switch (event) {
        .accepted => |info| {
            try testing.expectEqual(@as(u16, 0), info.conn_idx);
            try testing.expectEqual(@as(u16, 80), info.id.local_port);
            try testing.expectEqual(@as(u16, 5000), info.id.remote_port);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 1), ts.active_count);
}

test "TcpStack: write and poll produces segment" {
    var ts = TcpStack(16).init();
    ts.addLocalAddr(.{ 10, 0, 0, 1 });

    // Accept a connection
    var tcp_buf: [20]u8 = undefined;
    var hdr = header.tcp.MutableHeader.init(&tcp_buf) catch unreachable;
    hdr.setSrcPort(5000);
    hdr.setDstPort(80);
    hdr.setSeqNum(1000);
    hdr.setAckNum(0);
    hdr.setFlags(.{ .syn = true });
    hdr.setWindowSize(65535);
    // data offset already set to 5 by init()

    _ = ts.handleSegment(0, .{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, &tcp_buf);

    // Simulate completing handshake: send ACK of our SYN+ACK
    const slot = &ts.conns[0];
    slot.conn.sender.syn_sent = true;
    slot.conn.sender.syn_acked = true;
    slot.conn.sender.snd_nxt = 100001;
    slot.conn.sender.snd_una = 100001;
    slot.conn.state = .established;
    slot.conn.sender.nagle_enabled = false;

    // Write data
    const written = ts.write(0, "hello");
    try testing.expectEqual(@as(usize, 5), written);

    // Poll should produce a data segment
    var out: [4]TcpStack(16).Segment = undefined;
    const count = ts.poll(100, &out);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqual(@as(usize, 5), out[0].seg.payload_len);
}

test "TcpStack: close connection" {
    var ts = TcpStack(16).init();

    // Create a pre-established connection
    ts.conns[0] = .{
        .conn = Connection{
            .state = .established,
            .sender = @import("transport/tcp/sender.zig").Sender.init(1000, 1460),
            .receiver = @import("transport/tcp/receiver.zig").Receiver.init(2000, 65535),
        },
        .id = .{ .local_addr = .{ 10, 0, 0, 1 }, .local_port = 80, .remote_addr = .{ 10, 0, 0, 2 }, .remote_port = 5000 },
        .active = true,
    };
    ts.conns[0].conn.sender.syn_sent = true;
    ts.conns[0].conn.sender.syn_acked = true;
    ts.conns[0].conn.sender.snd_nxt = 1001;
    ts.conns[0].conn.sender.snd_una = 1001;
    ts.active_count = 1;

    ts.close(0);

    // Poll produces FIN
    var out: [4]TcpStack(16).Segment = undefined;
    const count = ts.poll(100, &out);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expect(out[0].seg.flags.fin);
}
