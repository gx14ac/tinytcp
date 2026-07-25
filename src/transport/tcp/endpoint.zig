// TCP Endpoint: State machine for a single TCP connection.
//
// Implements the core TCP state transitions (RFC 9293):
// CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT_1 → ...
// CLOSED → LISTEN → SYN_RECEIVED → ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED

const std = @import("std");
const tcp_header = @import("../../header/tcp.zig");

/// TCP connection state (tagged union for type-safe transitions).
pub const State = enum {
    closed,
    listen,
    syn_sent,
    syn_received,
    established,
    fin_wait_1,
    fin_wait_2,
    closing,
    time_wait,
    close_wait,
    last_ack,
};

/// TCP connection options negotiated during handshake.
pub const TcpOptions = struct {
    mss: u16 = 1460,
    window_scale: u8 = 0,
    sack_permitted: bool = false,
    timestamps: bool = false,
};

/// Sequence number arithmetic (wrapping comparison).
pub fn seqLt(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) < 0;
}

pub fn seqLte(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) <= 0;
}

pub fn seqGt(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) > 0;
}

pub fn seqGte(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) >= 0;
}

/// TCP endpoint representing one side of a connection.
pub const Endpoint = struct {
    state: State = .closed,

    // Local/remote identification
    local_addr: [4]u8 = .{ 0, 0, 0, 0 },
    local_port: u16 = 0,
    remote_addr: [4]u8 = .{ 0, 0, 0, 0 },
    remote_port: u16 = 0,

    // Send sequence variables
    snd_una: u32 = 0, // oldest unacknowledged
    snd_nxt: u32 = 0, // next to send
    snd_wnd: u32 = 0, // send window
    iss: u32 = 0, // initial send sequence number

    // Receive sequence variables
    rcv_nxt: u32 = 0, // next expected
    rcv_wnd: u32 = 65535, // receive window
    irs: u32 = 0, // initial receive sequence number

    // Negotiated options
    options: TcpOptions = .{},

    // Send buffer (simple fixed buffer for now)
    send_buf: [65536]u8 = undefined,
    send_buf_len: usize = 0,

    // Receive buffer
    recv_buf: [65536]u8 = undefined,
    recv_buf_len: usize = 0,

    /// Action to take after processing a segment.
    pub const Action = union(enum) {
        none,
        send_syn: SendSegment,
        send_syn_ack: SendSegment,
        send_ack: SendSegment,
        send_data: SendSegment,
        send_fin: SendSegment,
        send_rst: SendSegment,
        connection_established,
        connection_refused,
        connection_closed,
    };

    pub const SendSegment = struct {
        flags: tcp_header.Flags = .{},
        seq: u32 = 0,
        ack: u32 = 0,
        window: u16 = 0,
        payload: ?[]const u8 = null,
    };

    /// Initiate an active open (client → SYN_SENT).
    pub fn connect(self: *Endpoint, local_addr: [4]u8, local_port: u16, remote_addr: [4]u8, remote_port: u16, isn: u32) Action {
        self.local_addr = local_addr;
        self.local_port = local_port;
        self.remote_addr = remote_addr;
        self.remote_port = remote_port;
        self.iss = isn;
        self.snd_nxt = isn +% 1;
        self.snd_una = isn;
        self.state = .syn_sent;

        return .{ .send_syn = .{
            .flags = .{ .syn = true },
            .seq = isn,
            .ack = 0,
            .window = @intCast(self.rcv_wnd),
        } };
    }

    /// Passive open (server → LISTEN).
    pub fn listen(self: *Endpoint, local_addr: [4]u8, local_port: u16) void {
        self.local_addr = local_addr;
        self.local_port = local_port;
        self.state = .listen;
    }

    /// Process an inbound TCP segment.
    pub fn handleSegment(self: *Endpoint, seg_flags: tcp_header.Flags, seg_seq: u32, seg_ack: u32, seg_wnd: u16, payload: []const u8) Action {
        return switch (self.state) {
            .closed => self.handleClosed(seg_flags),
            .listen => self.handleListen(seg_flags, seg_seq),
            .syn_sent => self.handleSynSent(seg_flags, seg_seq, seg_ack, seg_wnd),
            .syn_received => self.handleSynReceived(seg_flags, seg_seq, seg_ack, seg_wnd),
            .established => self.handleEstablished(seg_flags, seg_seq, seg_ack, seg_wnd, payload),
            .fin_wait_1 => self.handleFinWait1(seg_flags, seg_seq, seg_ack),
            .fin_wait_2 => self.handleFinWait2(seg_flags, seg_seq),
            .close_wait => .none,
            .last_ack => self.handleLastAck(seg_flags, seg_ack),
            .closing => self.handleClosing(seg_flags, seg_ack),
            .time_wait => .none,
        };
    }

    fn handleClosed(self: *Endpoint, seg_flags: tcp_header.Flags) Action {
        _ = self;
        if (seg_flags.rst) return .none;
        return .{ .send_rst = .{ .flags = .{ .rst = true, .ack = true } } };
    }

    fn handleListen(self: *Endpoint, seg_flags: tcp_header.Flags, seg_seq: u32) Action {
        if (seg_flags.rst) return .none;
        if (seg_flags.syn) {
            // Received SYN: transition to SYN_RECEIVED, send SYN+ACK
            self.irs = seg_seq;
            self.rcv_nxt = seg_seq +% 1;
            self.state = .syn_received;

            return .{ .send_syn_ack = .{
                .flags = .{ .syn = true, .ack = true },
                .seq = self.iss,
                .ack = self.rcv_nxt,
                .window = @intCast(self.rcv_wnd),
            } };
        }
        return .none;
    }

    fn handleSynSent(self: *Endpoint, seg_flags: tcp_header.Flags, seg_seq: u32, seg_ack: u32, seg_wnd: u16) Action {
        if (seg_flags.rst) {
            if (seg_flags.ack) {
                self.state = .closed;
                return .connection_refused;
            }
            return .none;
        }

        if (seg_flags.syn and seg_flags.ack) {
            // SYN+ACK received: validate ACK, transition to ESTABLISHED
            if (seg_ack != self.snd_nxt) {
                return .{ .send_rst = .{ .flags = .{ .rst = true }, .seq = seg_ack } };
            }
            self.irs = seg_seq;
            self.rcv_nxt = seg_seq +% 1;
            self.snd_una = seg_ack;
            self.snd_wnd = @as(u32, seg_wnd);
            self.state = .established;

            return .{ .send_ack = .{
                .flags = .{ .ack = true },
                .seq = self.snd_nxt,
                .ack = self.rcv_nxt,
                .window = @intCast(self.rcv_wnd),
            } };
        }

        if (seg_flags.syn) {
            // Simultaneous open: SYN without ACK
            self.irs = seg_seq;
            self.rcv_nxt = seg_seq +% 1;
            self.state = .syn_received;
            return .{ .send_syn_ack = .{
                .flags = .{ .syn = true, .ack = true },
                .seq = self.iss,
                .ack = self.rcv_nxt,
                .window = @intCast(self.rcv_wnd),
            } };
        }

        return .none;
    }

    fn handleSynReceived(self: *Endpoint, seg_flags: tcp_header.Flags, _: u32, seg_ack: u32, seg_wnd: u16) Action {
        if (seg_flags.rst) {
            self.state = .closed;
            return .connection_refused;
        }

        if (seg_flags.ack) {
            // ACK of our SYN+ACK: transition to ESTABLISHED
            if (seg_ack == self.iss +% 1) {
                self.snd_una = seg_ack;
                self.snd_nxt = seg_ack;
                self.snd_wnd = @as(u32, seg_wnd);
                self.state = .established;
                return .connection_established;
            }
        }

        return .none;
    }

    fn handleEstablished(self: *Endpoint, seg_flags: tcp_header.Flags, seg_seq: u32, seg_ack: u32, seg_wnd: u16, payload: []const u8) Action {
        if (seg_flags.rst) {
            self.state = .closed;
            return .connection_closed;
        }

        // Process ACK
        if (seg_flags.ack) {
            if (seqGt(seg_ack, self.snd_una) and seqLte(seg_ack, self.snd_nxt)) {
                self.snd_una = seg_ack;
            }
            self.snd_wnd = @as(u32, seg_wnd);
        }

        // Process data
        if (payload.len > 0 and seg_seq == self.rcv_nxt) {
            const space = self.recv_buf.len - self.recv_buf_len;
            const copy_len = @min(payload.len, space);
            if (copy_len > 0) {
                @memcpy(self.recv_buf[self.recv_buf_len .. self.recv_buf_len + copy_len], payload[0..copy_len]);
                self.recv_buf_len += copy_len;
                self.rcv_nxt +%= @intCast(copy_len);
            }
        }

        // Process FIN
        if (seg_flags.fin) {
            self.rcv_nxt +%= 1;
            self.state = .close_wait;
            return .{ .send_ack = .{
                .flags = .{ .ack = true },
                .seq = self.snd_nxt,
                .ack = self.rcv_nxt,
                .window = @intCast(self.rcv_wnd),
            } };
        }

        // Send ACK if we received data
        if (payload.len > 0) {
            return .{ .send_ack = .{
                .flags = .{ .ack = true },
                .seq = self.snd_nxt,
                .ack = self.rcv_nxt,
                .window = @intCast(self.rcv_wnd),
            } };
        }

        return .none;
    }

    fn handleFinWait1(self: *Endpoint, seg_flags: tcp_header.Flags, _: u32, seg_ack: u32) Action {
        if (seg_flags.ack and seg_ack == self.snd_nxt) {
            if (seg_flags.fin) {
                // FIN+ACK: go to TIME_WAIT
                self.rcv_nxt +%= 1;
                self.state = .time_wait;
                return .{ .send_ack = .{
                    .flags = .{ .ack = true },
                    .seq = self.snd_nxt,
                    .ack = self.rcv_nxt,
                    .window = @intCast(self.rcv_wnd),
                } };
            }
            // ACK only: go to FIN_WAIT_2
            self.state = .fin_wait_2;
        } else if (seg_flags.fin) {
            // Simultaneous close
            self.rcv_nxt +%= 1;
            self.state = .closing;
            return .{ .send_ack = .{
                .flags = .{ .ack = true },
                .seq = self.snd_nxt,
                .ack = self.rcv_nxt,
                .window = @intCast(self.rcv_wnd),
            } };
        }
        return .none;
    }

    fn handleFinWait2(self: *Endpoint, seg_flags: tcp_header.Flags, _: u32) Action {
        if (seg_flags.fin) {
            self.rcv_nxt +%= 1;
            self.state = .time_wait;
            return .{ .send_ack = .{
                .flags = .{ .ack = true },
                .seq = self.snd_nxt,
                .ack = self.rcv_nxt,
                .window = @intCast(self.rcv_wnd),
            } };
        }
        return .none;
    }

    fn handleLastAck(self: *Endpoint, seg_flags: tcp_header.Flags, seg_ack: u32) Action {
        if (seg_flags.ack and seg_ack == self.snd_nxt) {
            self.state = .closed;
            return .connection_closed;
        }
        return .none;
    }

    fn handleClosing(self: *Endpoint, seg_flags: tcp_header.Flags, seg_ack: u32) Action {
        if (seg_flags.ack and seg_ack == self.snd_nxt) {
            self.state = .time_wait;
        }
        return .none;
    }

    /// Initiate close (active close from ESTABLISHED).
    pub fn close(self: *Endpoint) Action {
        switch (self.state) {
            .established => {
                self.state = .fin_wait_1;
                const action = Action{ .send_fin = .{
                    .flags = .{ .fin = true, .ack = true },
                    .seq = self.snd_nxt,
                    .ack = self.rcv_nxt,
                    .window = @intCast(self.rcv_wnd),
                } };
                self.snd_nxt +%= 1; // FIN consumes one sequence number
                return action;
            },
            .close_wait => {
                self.state = .last_ack;
                const action = Action{ .send_fin = .{
                    .flags = .{ .fin = true, .ack = true },
                    .seq = self.snd_nxt,
                    .ack = self.rcv_nxt,
                    .window = @intCast(self.rcv_wnd),
                } };
                self.snd_nxt +%= 1;
                return action;
            },
            else => return .none,
        }
    }

    /// Write data to the send buffer. Returns number of bytes accepted.
    pub fn write(self: *Endpoint, data: []const u8) usize {
        if (self.state != .established) return 0;
        const space = self.send_buf.len - self.send_buf_len;
        const copy_len = @min(data.len, space);
        @memcpy(self.send_buf[self.send_buf_len .. self.send_buf_len + copy_len], data[0..copy_len]);
        self.send_buf_len += copy_len;
        return copy_len;
    }

    /// Read data from the receive buffer. Returns slice of data read.
    pub fn read(self: *Endpoint, buf: []u8) usize {
        const copy_len = @min(buf.len, self.recv_buf_len);
        if (copy_len == 0) return 0;
        @memcpy(buf[0..copy_len], self.recv_buf[0..copy_len]);
        // Shift remaining data
        if (copy_len < self.recv_buf_len) {
            std.mem.copyForwards(u8, self.recv_buf[0 .. self.recv_buf_len - copy_len], self.recv_buf[copy_len..self.recv_buf_len]);
        }
        self.recv_buf_len -= copy_len;
        return copy_len;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "TCP: 3-way handshake (client side)" {
    var ep = Endpoint{};

    // Client sends SYN
    const syn_action = ep.connect(.{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 80, 1000);
    try testing.expectEqual(State.syn_sent, ep.state);
    switch (syn_action) {
        .send_syn => |seg| {
            try testing.expect(seg.flags.syn);
            try testing.expectEqual(@as(u32, 1000), seg.seq);
        },
        else => return error.TestUnexpectedResult,
    }

    // Client receives SYN+ACK (server ISN=2000, ACK=1001)
    const ack_action = ep.handleSegment(
        .{ .syn = true, .ack = true },
        2000, // seq
        1001, // ack (ISS+1)
        32768, // window
        &.{},
    );
    try testing.expectEqual(State.established, ep.state);
    switch (ack_action) {
        .send_ack => |seg| {
            try testing.expect(seg.flags.ack);
            try testing.expectEqual(@as(u32, 2001), seg.ack);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "TCP: 3-way handshake (server side)" {
    var ep = Endpoint{ .iss = 2000 };
    ep.listen(.{ 10, 0, 0, 2 }, 80);
    try testing.expectEqual(State.listen, ep.state);

    // Server receives SYN (client ISN=1000)
    const syn_ack_action = ep.handleSegment(
        .{ .syn = true },
        1000, // seq
        0, // ack (irrelevant)
        65535,
        &.{},
    );
    try testing.expectEqual(State.syn_received, ep.state);
    switch (syn_ack_action) {
        .send_syn_ack => |seg| {
            try testing.expect(seg.flags.syn);
            try testing.expect(seg.flags.ack);
            try testing.expectEqual(@as(u32, 1001), seg.ack);
        },
        else => return error.TestUnexpectedResult,
    }

    // Server receives ACK (completing handshake)
    const estab_action = ep.handleSegment(
        .{ .ack = true },
        1001, // seq
        2001, // ack (server ISS + 1)
        65535,
        &.{},
    );
    try testing.expectEqual(State.established, ep.state);
    try testing.expectEqual(Endpoint.Action.connection_established, estab_action);
}

test "TCP: data transfer" {
    // Set up established connection
    var ep = Endpoint{
        .state = .established,
        .snd_nxt = 1001,
        .snd_una = 1001,
        .rcv_nxt = 2001,
        .snd_wnd = 65535,
    };

    // Receive data
    const action = ep.handleSegment(
        .{ .ack = true },
        2001, // seq = rcv_nxt
        1001, // ack
        65535,
        "hello",
    );
    try testing.expectEqual(@as(usize, 5), ep.recv_buf_len);
    try testing.expectEqualSlices(u8, "hello", ep.recv_buf[0..5]);
    try testing.expectEqual(@as(u32, 2006), ep.rcv_nxt);

    switch (action) {
        .send_ack => |seg| {
            try testing.expectEqual(@as(u32, 2006), seg.ack);
        },
        else => return error.TestUnexpectedResult,
    }

    // Read the data
    var buf: [10]u8 = undefined;
    const n = ep.read(&buf);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualSlices(u8, "hello", buf[0..5]);
}

test "TCP: connection close (active)" {
    var ep = Endpoint{
        .state = .established,
        .snd_nxt = 1001,
        .snd_una = 1001,
        .rcv_nxt = 2001,
    };

    // Active close: send FIN
    const fin_action = ep.close();
    try testing.expectEqual(State.fin_wait_1, ep.state);
    switch (fin_action) {
        .send_fin => |seg| {
            try testing.expect(seg.flags.fin);
            try testing.expect(seg.flags.ack);
        },
        else => return error.TestUnexpectedResult,
    }

    // Receive FIN+ACK
    const ack_action = ep.handleSegment(
        .{ .fin = true, .ack = true },
        2001,
        1002, // ACK of our FIN (snd_nxt after FIN = 1002)
        65535,
        &.{},
    );
    try testing.expectEqual(State.time_wait, ep.state);
    switch (ack_action) {
        .send_ack => {},
        else => return error.TestUnexpectedResult,
    }
}

test "TCP: sequence number arithmetic" {
    // Wrapping comparison
    try testing.expect(seqLt(0xFFFFFFFF, 0x00000001)); // wrap around
    try testing.expect(seqGt(0x00000001, 0xFFFFFFFF)); // wrap around
    try testing.expect(seqLt(100, 200));
    try testing.expect(!seqLt(200, 100));
}
