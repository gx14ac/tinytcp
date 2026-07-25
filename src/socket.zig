// Socket API — POSIX-like socket interface over the tinytcp stack.
//
// Provides TcpSocket and UdpSocket with familiar semantics:
// - bind, listen, accept, connect, read, write, close
// - sendto, recvfrom for UDP
// - Non-blocking with readiness polling
// - POSIX-compatible error codes
// - Socket options (SO_REUSEADDR, SO_KEEPALIVE, TCP_NODELAY, SO_LINGER)
//
// Sans-IO: wraps FullStack; no system calls.

const std = @import("std");
const full_stack_mod = @import("full_stack.zig");

/// Socket error codes (POSIX-compatible naming).
pub const SocketError = enum {
    success,
    /// Connection refused by peer (RST received).
    econnrefused,
    /// Connection timed out.
    etimedout,
    /// Connection reset by peer.
    econnreset,
    /// Address already in use.
    eaddrinuse,
    /// Operation would block (non-blocking mode).
    ewouldblock,
    /// Not connected.
    enotconn,
    /// Already connected.
    eisconn,
    /// No buffer space available.
    enobufs,
    /// Bad file descriptor (invalid socket).
    ebadf,
    /// Connection aborted.
    econnaborted,
    /// Network unreachable.
    enetunreach,
};

/// Socket readiness flags for polling.
pub const Readiness = struct {
    readable: bool = false,
    writable: bool = false,
    error_occurred: bool = false,
    hangup: bool = false,
};

/// Socket address.
pub const SockAddr = struct {
    addr: [4]u8 = .{ 0, 0, 0, 0 },
    port: u16 = 0,
};

/// Socket options.
pub const SockOpt = enum {
    so_reuseaddr,
    so_keepalive,
    so_linger,
    tcp_nodelay,
};

/// Linger option value.
pub const LingerOpt = struct {
    enabled: bool = false,
    timeout_ms: u64 = 0,
};


/// TCP Socket — stream-oriented connection socket.
pub const TcpSocket = struct {
    /// Internal connection index in FullStack.
    conn_idx: ?u16 = null,
    /// Socket state.
    state: State = .closed,
    /// Last error.
    last_error: SocketError = .success,
    /// Local binding.
    local: SockAddr = .{},
    /// Remote address (set after connect or accept).
    remote: SockAddr = .{},
    /// Socket options.
    reuse_addr: bool = false,
    keepalive: bool = false,
    nodelay: bool = false,
    linger: LingerOpt = .{},

    pub const State = enum {
        closed,
        bound,
        listening,
        connecting,
        connected,
        closing,
    };

    /// Bind to a local address/port.
    pub fn bind(self: *TcpSocket, addr: SockAddr) SocketError {
        if (self.state != .closed) return .eaddrinuse;
        self.local = addr;
        self.state = .bound;
        return .success;
    }

    /// Start listening for incoming connections.
    pub fn listen(self: *TcpSocket, stack: anytype, backlog: u16) SocketError {
        if (self.state != .bound) return .ebadf;
        if (!stack.listen(self.local.port, backlog)) return .enobufs;
        self.state = .listening;
        return .success;
    }

    /// Accept a new connection from the listen queue.
    /// Returns a new TcpSocket in connected state, or ewouldblock if none pending.
    pub fn doAccept(self: *TcpSocket, stack: anytype) struct { sock: TcpSocket, err: SocketError } {
        if (self.state != .listening) return .{ .sock = .{}, .err = .ebadf };

        if (stack.accept()) |idx| {
            const id = stack.connId(idx) orelse return .{ .sock = .{}, .err = .econnaborted };
            return .{
                .sock = .{
                    .conn_idx = idx,
                    .state = .connected,
                    .local = .{ .addr = id.local_addr, .port = id.local_port },
                    .remote = .{ .addr = id.remote_addr, .port = id.remote_port },
                },
                .err = .success,
            };
        }
        return .{ .sock = .{}, .err = .ewouldblock };
    }

    /// Initiate a connection to a remote address.
    pub fn doConnect(self: *TcpSocket, stack: anytype, now_ms: u64, remote: SockAddr) SocketError {
        if (self.state == .connected) return .eisconn;
        if (self.state != .closed and self.state != .bound) return .ebadf;

        const local_port = if (self.local.port != 0) self.local.port else stack.allocEphemeralPort();

        const idx = stack.connect(now_ms, remote.addr, remote.port, local_port) orelse return .enobufs;

        self.conn_idx = idx;
        self.state = .connecting;
        self.remote = remote;
        self.local.port = local_port;
        return .success;
    }

    /// Write data to the connection. Returns bytes written or 0 on error.
    pub fn doWrite(self: *TcpSocket, stack: anytype, data: []const u8) struct { written: usize, err: SocketError } {
        if (self.state != .connected) return .{ .written = 0, .err = .enotconn };
        const idx = self.conn_idx orelse return .{ .written = 0, .err = .ebadf };
        const n = stack.write(idx, data);
        if (n == 0 and data.len > 0) return .{ .written = 0, .err = .ewouldblock };
        return .{ .written = n, .err = .success };
    }

    /// Read data from the connection. Returns bytes read or 0 on error.
    /// Returns { .read_bytes = 0, .err = .success } on EOF (peer closed).
    /// Returns { .read_bytes = 0, .err = .ewouldblock } when no data available.
    pub fn doRead(self: *TcpSocket, stack: anytype, buf: []u8) struct { read_bytes: usize, err: SocketError } {
        if (self.state != .connected) return .{ .read_bytes = 0, .err = .enotconn };
        const idx = self.conn_idx orelse return .{ .read_bytes = 0, .err = .ebadf };
        const n = stack.read(idx, buf);
        if (n == 0) {
            // Distinguish EOF from "no data yet"
            const conn_state = stack.connState(idx);
            if (conn_state == null or conn_state.? == .close_wait or conn_state.? == .closed or conn_state.? == .time_wait) {
                return .{ .read_bytes = 0, .err = .success }; // EOF
            }
            return .{ .read_bytes = 0, .err = .ewouldblock };
        }
        return .{ .read_bytes = n, .err = .success };
    }

    /// Close the socket.
    pub fn doClose(self: *TcpSocket, stack: anytype) void {
        if (self.conn_idx) |idx| {
            if (self.linger.enabled) {
                stack.setLinger(idx, true, self.linger.timeout_ms);
            }
            stack.close(idx);
            self.state = .closing;
        } else {
            self.state = .closed;
        }
    }

    /// Shutdown write direction.
    pub fn shutdownWrite(self: *TcpSocket, stack: anytype) SocketError {
        if (self.state != .connected) return .enotconn;
        const idx = self.conn_idx orelse return .ebadf;
        stack.shutdownWrite(idx);
        return .success;
    }

    /// Shutdown read direction.
    pub fn shutdownRead(self: *TcpSocket, stack: anytype) SocketError {
        if (self.state != .connected) return .enotconn;
        const idx = self.conn_idx orelse return .ebadf;
        stack.shutdownRead(idx);
        return .success;
    }

    /// Set a socket option.
    pub fn setOpt(self: *TcpSocket, stack: anytype, opt: SockOpt, enabled: bool) void {
        switch (opt) {
            .so_reuseaddr => self.reuse_addr = enabled,
            .so_keepalive => {
                self.keepalive = enabled;
                if (self.conn_idx) |idx| stack.setKeepalive(idx, enabled);
            },
            .tcp_nodelay => {
                self.nodelay = enabled;
                if (self.conn_idx) |idx| stack.setNoDelay(idx, enabled);
            },
            .so_linger => self.linger.enabled = enabled,
        }
    }

    /// Set linger timeout.
    pub fn setLingerTimeout(self: *TcpSocket, timeout_ms: u64) void {
        self.linger.timeout_ms = timeout_ms;
    }

    /// Poll readiness state.
    /// readable = data available in recv buffer OR peer closed (EOF readable).
    /// writable = send buffer has space.
    pub fn pollReadiness(self: *const TcpSocket, stack: anytype) Readiness {
        var r = Readiness{};
        switch (self.state) {
            .connected => {
                const idx = self.conn_idx orelse return r;
                const conn_state = stack.connState(idx) orelse {
                    r.hangup = true;
                    r.error_occurred = true;
                    return r;
                };
                // readable: hasReadableData or EOF state
                if (@hasDecl(@TypeOf(stack.*), "hasReadableData")) {
                    r.readable = stack.hasReadableData(idx);
                } else {
                    // Fallback: EOF states are always readable (return 0 = EOF)
                    r.readable = (conn_state == .close_wait or conn_state == .closed);
                }
                // writable: canWrite
                if (@hasDecl(@TypeOf(stack.*), "canWrite")) {
                    r.writable = stack.canWrite(idx);
                } else {
                    // Fallback: assume writable if connection is established
                    r.writable = (conn_state == .established);
                }
            },
            .connecting => {
                const idx = self.conn_idx orelse return r;
                const conn_state = stack.connState(idx) orelse {
                    r.error_occurred = true;
                    return r;
                };
                if (conn_state == .established) {
                    r.writable = true;
                }
            },
            .listening => {
                // readable = connection in accept queue
                r.readable = true;
            },
            else => {},
        }
        return r;
    }

    /// Update socket state based on stack events. Call after poll/advance.
    pub fn updateState(self: *TcpSocket, stack: anytype) void {
        if (self.conn_idx == null) return;
        const idx = self.conn_idx.?;
        const conn_state = stack.connState(idx) orelse {
            // Slot freed by FullStack — safe to release
            self.state = .closed;
            self.conn_idx = null;
            return;
        };
        switch (conn_state) {
            .established => {
                if (self.state == .connecting) {
                    self.state = .connected;
                }
            },
            .time_wait => {
                // Keep conn_idx so FullStack retains the slot until TIME_WAIT expires.
                // Socket is logically closed from the application's perspective.
                self.state = .closed;
            },
            .closed => {
                self.state = .closed;
                self.conn_idx = null;
            },
            else => {},
        }
    }
};

/// UDP Socket — datagram socket.
pub const UdpSocket = struct {
    /// Internal endpoint index in FullStack.
    ep_idx: ?u16 = null,
    /// Socket state.
    state: State = .closed,
    /// Last error.
    last_error: SocketError = .success,
    /// Local binding.
    local: SockAddr = .{},
    /// Connected remote (for send/recv without address).
    remote: ?SockAddr = null,
    /// Socket options.
    reuse_addr: bool = false,

    pub const State = enum {
        closed,
        bound,
        connected,
    };

    /// Bind to a local port.
    pub fn doBind(self: *UdpSocket, stack: anytype, addr: SockAddr) SocketError {
        if (self.state != .closed) return .eaddrinuse;
        const idx = stack.udpBind(addr.port) orelse return .enobufs;
        self.ep_idx = idx;
        self.local = addr;
        self.state = .bound;
        return .success;
    }

    /// Connect to a remote address (sets default destination).
    pub fn doConnect(self: *UdpSocket, stack: anytype, remote: SockAddr) SocketError {
        if (self.state == .closed) return .ebadf;
        const idx = self.ep_idx orelse return .ebadf;
        stack.udpConnect(idx, remote.addr, remote.port);
        self.remote = remote;
        self.state = .connected;
        return .success;
    }

    /// Send a datagram to a specific address.
    pub fn sendTo(self: *UdpSocket, stack: anytype, dst: SockAddr, data: []const u8) SocketError {
        if (self.state == .closed) return .ebadf;
        const idx = self.ep_idx orelse return .ebadf;
        if (!stack.udpSendTo(idx, dst.addr, dst.port, data)) return .enobufs;
        return .success;
    }

    /// Send a datagram to the connected remote.
    pub fn send(self: *UdpSocket, stack: anytype, data: []const u8) SocketError {
        if (self.remote == null) return .enotconn;
        const idx = self.ep_idx orelse return .ebadf;
        if (!stack.udpSend(idx, data)) return .enobufs;
        return .success;
    }

    /// Receive a datagram. Returns source address, data length, and error.
    pub fn recvFrom(self: *UdpSocket, stack: anytype, buf: []u8) struct { from: SockAddr, len: usize, err: SocketError } {
        if (self.state == .closed) return .{ .from = .{}, .len = 0, .err = .ebadf };
        const idx = self.ep_idx orelse return .{ .from = .{}, .len = 0, .err = .ebadf };
        if (stack.udpRecv(idx)) |dgram| {
            const copy_len = @min(buf.len, dgram.data.len);
            @memcpy(buf[0..copy_len], dgram.data[0..copy_len]);
            return .{
                .from = .{ .addr = dgram.src_addr, .port = dgram.src_port },
                .len = copy_len,
                .err = .success,
            };
        }
        return .{ .from = .{}, .len = 0, .err = .ewouldblock };
    }

    /// Close the socket.
    pub fn doClose(self: *UdpSocket, stack: anytype) void {
        if (self.ep_idx) |idx| {
            stack.udpClose(idx);
        }
        self.state = .closed;
        self.ep_idx = null;
        self.remote = null;
    }

    /// Poll readiness.
    pub fn pollReadiness(self: *const UdpSocket, stack: anytype) Readiness {
        var r = Readiness{};
        if (self.state == .closed) return r;
        const idx = self.ep_idx orelse return r;
        r.writable = true;
        if (stack.udpAvailable(idx) > 0) {
            r.readable = true;
        }
        return r;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "TcpSocket: bind" {
    var sock = TcpSocket{};
    const err = sock.bind(.{ .addr = .{ 0, 0, 0, 0 }, .port = 8080 });
    try testing.expectEqual(SocketError.success, err);
    try testing.expectEqual(TcpSocket.State.bound, sock.state);
    try testing.expectEqual(@as(u16, 8080), sock.local.port);
}

test "TcpSocket: double bind fails" {
    var sock = TcpSocket{};
    _ = sock.bind(.{ .addr = .{ 0, 0, 0, 0 }, .port = 8080 });
    const err = sock.bind(.{ .addr = .{ 0, 0, 0, 0 }, .port = 9090 });
    try testing.expectEqual(SocketError.eaddrinuse, err);
}

test "TcpSocket: listen requires bound" {
    var sock = TcpSocket{};
    var mock = MockStack{};
    const err = sock.listen(&mock, 128);
    try testing.expectEqual(SocketError.ebadf, err);
}

test "TcpSocket: listen on bound socket" {
    var sock = TcpSocket{};
    _ = sock.bind(.{ .port = 80 });
    var mock = MockStack{};
    const err = sock.listen(&mock, 64);
    try testing.expectEqual(SocketError.success, err);
    try testing.expectEqual(TcpSocket.State.listening, sock.state);
    try testing.expectEqual(@as(u16, 80), mock.listen_port);
    try testing.expectEqual(@as(u16, 64), mock.listen_backlog);
}

test "TcpSocket: accept returns ewouldblock when empty" {
    var sock = TcpSocket{};
    _ = sock.bind(.{ .port = 80 });
    var mock = MockStack{};
    _ = sock.listen(&mock, 64);
    const result = sock.doAccept(&mock);
    try testing.expectEqual(SocketError.ewouldblock, result.err);
}

test "TcpSocket: connect" {
    var sock = TcpSocket{};
    _ = sock.bind(.{ .port = 5000 });
    var mock = MockStack{};
    mock.connect_result = 0;
    const err = sock.doConnect(&mock, 1000, .{ .addr = .{ 10, 0, 0, 1 }, .port = 80 });
    try testing.expectEqual(SocketError.success, err);
    try testing.expectEqual(TcpSocket.State.connecting, sock.state);
    try testing.expectEqual(@as(u16, 0), sock.conn_idx.?);
}

test "TcpSocket: connect when already connected" {
    var sock = TcpSocket{ .state = .connected, .conn_idx = 0 };
    var mock = MockStack{};
    const err = sock.doConnect(&mock, 1000, .{ .addr = .{ 10, 0, 0, 1 }, .port = 80 });
    try testing.expectEqual(SocketError.eisconn, err);
}

test "TcpSocket: write requires connected" {
    var sock = TcpSocket{};
    var mock = MockStack{};
    const result = sock.doWrite(&mock, "hello");
    try testing.expectEqual(SocketError.enotconn, result.err);
}

test "TcpSocket: write on connected socket" {
    var sock = TcpSocket{ .state = .connected, .conn_idx = 0 };
    var mock = MockStack{};
    mock.write_result = 5;
    const result = sock.doWrite(&mock, "hello");
    try testing.expectEqual(SocketError.success, result.err);
    try testing.expectEqual(@as(usize, 5), result.written);
}

test "TcpSocket: read requires connected" {
    var sock = TcpSocket{};
    var mock = MockStack{};
    var buf: [64]u8 = undefined;
    const result = sock.doRead(&mock, &buf);
    try testing.expectEqual(SocketError.enotconn, result.err);
}

test "TcpSocket: setOpt tcp_nodelay" {
    var sock = TcpSocket{ .state = .connected, .conn_idx = 0 };
    var mock = MockStack{};
    sock.setOpt(&mock, .tcp_nodelay, true);
    try testing.expect(sock.nodelay);
    try testing.expect(mock.nodelay_set);
}

test "TcpSocket: setOpt so_keepalive" {
    var sock = TcpSocket{ .state = .connected, .conn_idx = 0 };
    var mock = MockStack{};
    sock.setOpt(&mock, .so_keepalive, true);
    try testing.expect(sock.keepalive);
    try testing.expect(mock.keepalive_set);
}

test "TcpSocket: close" {
    var sock = TcpSocket{ .state = .connected, .conn_idx = 0 };
    var mock = MockStack{};
    sock.doClose(&mock);
    try testing.expectEqual(TcpSocket.State.closing, sock.state);
    try testing.expect(mock.close_called);
}

test "TcpSocket: close with linger" {
    var sock = TcpSocket{ .state = .connected, .conn_idx = 0 };
    sock.linger = .{ .enabled = true, .timeout_ms = 5000 };
    var mock = MockStack{};
    sock.doClose(&mock);
    try testing.expect(mock.linger_set);
    try testing.expect(mock.close_called);
}

test "TcpSocket: shutdownWrite requires connected" {
    var sock = TcpSocket{};
    var mock = MockStack{};
    const err = sock.shutdownWrite(&mock);
    try testing.expectEqual(SocketError.enotconn, err);
}

test "TcpSocket: updateState connecting to connected" {
    var sock = TcpSocket{ .state = .connecting, .conn_idx = 0 };
    var mock = MockStack{};
    mock.conn_state = .established;
    sock.updateState(&mock);
    try testing.expectEqual(TcpSocket.State.connected, sock.state);
}

test "TcpSocket: updateState to closed on inactive" {
    var sock = TcpSocket{ .state = .connected, .conn_idx = 0 };
    var mock = MockStack{};
    mock.conn_state = null;
    sock.updateState(&mock);
    try testing.expectEqual(TcpSocket.State.closed, sock.state);
    try testing.expect(sock.conn_idx == null);
}

test "TcpSocket: updateState TIME_WAIT keeps conn_idx" {
    var sock = TcpSocket{ .state = .closing, .conn_idx = 0 };
    var mock = MockStack{};
    mock.conn_state = .time_wait;
    sock.updateState(&mock);
    try testing.expectEqual(TcpSocket.State.closed, sock.state);
    // conn_idx retained so FullStack slot stays until TIME_WAIT expires
    try testing.expectEqual(@as(?u16, 0), sock.conn_idx);
}

test "TcpSocket: doClose on unconnected socket goes to closed" {
    var sock = TcpSocket{};
    _ = sock.bind(.{ .port = 8080 });
    var mock = MockStack{};
    sock.doClose(&mock);
    try testing.expectEqual(TcpSocket.State.closed, sock.state);
    try testing.expect(!mock.close_called);
}

test "TcpSocket: doRead returns EOF on close_wait" {
    var sock = TcpSocket{ .state = .connected, .conn_idx = 0 };
    var mock = MockStack{};
    mock.read_result = 0;
    mock.conn_state = .close_wait;
    var buf: [64]u8 = undefined;
    const result = sock.doRead(&mock, &buf);
    // EOF: read_bytes=0, err=success (not ewouldblock)
    try testing.expectEqual(@as(usize, 0), result.read_bytes);
    try testing.expectEqual(SocketError.success, result.err);
}

test "TcpSocket: doRead returns ewouldblock when no data" {
    var sock = TcpSocket{ .state = .connected, .conn_idx = 0 };
    var mock = MockStack{};
    mock.read_result = 0;
    mock.conn_state = .established;
    var buf: [64]u8 = undefined;
    const result = sock.doRead(&mock, &buf);
    try testing.expectEqual(@as(usize, 0), result.read_bytes);
    try testing.expectEqual(SocketError.ewouldblock, result.err);
}

test "TcpSocket: pollReadiness uses hasReadableData" {
    var sock = TcpSocket{ .state = .connected, .conn_idx = 0 };
    var mock = MockStack{};
    mock.conn_state = .established;
    mock.has_readable_data = false;
    mock.can_write = false;

    const r1 = sock.pollReadiness(&mock);
    try testing.expect(!r1.readable);
    try testing.expect(!r1.writable);

    mock.has_readable_data = true;
    mock.can_write = true;
    const r2 = sock.pollReadiness(&mock);
    try testing.expect(r2.readable);
    try testing.expect(r2.writable);
}

test "TcpSocket: ephemeral port increments" {
    var sock1 = TcpSocket{};
    var sock2 = TcpSocket{};
    var mock = MockStack{};
    mock.connect_result = 0;
    _ = sock1.doConnect(&mock, 1000, .{ .addr = .{ 10, 0, 0, 1 }, .port = 80 });
    mock.connect_result = 1;
    _ = sock2.doConnect(&mock, 1000, .{ .addr = .{ 10, 0, 0, 1 }, .port = 80 });
    try testing.expect(sock1.local.port != sock2.local.port);
}

test "UdpSocket: bind" {
    var sock = UdpSocket{};
    var mock = MockStack{};
    mock.udp_bind_result = 0;
    const err = sock.doBind(&mock, .{ .port = 5353 });
    try testing.expectEqual(SocketError.success, err);
    try testing.expectEqual(UdpSocket.State.bound, sock.state);
    try testing.expectEqual(@as(u16, 0), sock.ep_idx.?);
}

test "UdpSocket: double bind fails" {
    var sock = UdpSocket{ .state = .bound, .ep_idx = 0 };
    var mock = MockStack{};
    const err = sock.doBind(&mock, .{ .port = 5354 });
    try testing.expectEqual(SocketError.eaddrinuse, err);
}

test "UdpSocket: sendTo" {
    var sock = UdpSocket{ .state = .bound, .ep_idx = 0 };
    var mock = MockStack{};
    mock.udp_send_result = true;
    const err = sock.sendTo(&mock, .{ .addr = .{ 10, 0, 0, 1 }, .port = 53 }, "query");
    try testing.expectEqual(SocketError.success, err);
}

test "UdpSocket: send requires connected" {
    var sock = UdpSocket{ .state = .bound, .ep_idx = 0 };
    var mock = MockStack{};
    const err = sock.send(&mock, "data");
    try testing.expectEqual(SocketError.enotconn, err);
}

test "UdpSocket: connect and send" {
    var sock = UdpSocket{ .state = .bound, .ep_idx = 0 };
    var mock = MockStack{};
    mock.udp_send_result = true;
    const err1 = sock.doConnect(&mock, .{ .addr = .{ 8, 8, 8, 8 }, .port = 53 });
    try testing.expectEqual(SocketError.success, err1);
    try testing.expectEqual(UdpSocket.State.connected, sock.state);

    const err2 = sock.send(&mock, "query");
    try testing.expectEqual(SocketError.success, err2);
}

test "UdpSocket: recvFrom when empty" {
    var sock = UdpSocket{ .state = .bound, .ep_idx = 0 };
    var mock = MockStack{};
    var buf: [64]u8 = undefined;
    const result = sock.recvFrom(&mock, &buf);
    try testing.expectEqual(SocketError.ewouldblock, result.err);
}

test "UdpSocket: close" {
    var sock = UdpSocket{ .state = .bound, .ep_idx = 0 };
    var mock = MockStack{};
    sock.doClose(&mock);
    try testing.expectEqual(UdpSocket.State.closed, sock.state);
    try testing.expect(sock.ep_idx == null);
    try testing.expect(mock.udp_close_called);
}

test "UdpSocket: pollReadiness" {
    var sock = UdpSocket{ .state = .bound, .ep_idx = 0 };
    var mock = MockStack{};
    mock.udp_available_val = 2;
    const r = sock.pollReadiness(&mock);
    try testing.expect(r.readable);
    try testing.expect(r.writable);
}

// ============================================================================
// Mock stack for unit testing socket layer in isolation.
// ============================================================================

const tcp_connection = @import("transport/tcp/connection.zig");

const MockStack = struct {
    listen_port: u16 = 0,
    listen_backlog: u16 = 0,
    connect_result: ?u16 = null,
    write_result: usize = 0,
    read_result: usize = 0,
    nodelay_set: bool = false,
    keepalive_set: bool = false,
    close_called: bool = false,
    linger_set: bool = false,
    shutdown_write_called: bool = false,
    shutdown_read_called: bool = false,
    conn_state: ?tcp_connection.State = .established,
    accept_result: ?u16 = null,
    conn_id: ?full_stack_mod.ConnId = null,
    has_readable_data: bool = false,
    can_write: bool = true,

    udp_bind_result: ?u16 = null,
    udp_send_result: bool = false,
    udp_close_called: bool = false,
    udp_available_val: usize = 0,
    ephemeral_port_counter: u16 = 49152,

    pub fn listen(self: *MockStack, port: u16, backlog: u16) bool {
        self.listen_port = port;
        self.listen_backlog = backlog;
        return true;
    }

    pub fn accept(self: *MockStack) ?u16 {
        return self.accept_result;
    }

    pub fn connId(self: *MockStack, _: u16) ?full_stack_mod.ConnId {
        return self.conn_id;
    }

    pub fn connect(self: *MockStack, _: u64, _: [4]u8, _: u16, _: u16) ?u16 {
        return self.connect_result;
    }

    pub fn allocEphemeralPort(self: *MockStack) u16 {
        const port = self.ephemeral_port_counter;
        self.ephemeral_port_counter = if (self.ephemeral_port_counter >= 65535) 49152 else self.ephemeral_port_counter + 1;
        return port;
    }

    pub fn write(self: *MockStack, _: u16, _: []const u8) usize {
        return self.write_result;
    }

    pub fn read(self: *MockStack, _: u16, _: []u8) usize {
        return self.read_result;
    }

    pub fn close(self: *MockStack, _: u16) void {
        self.close_called = true;
    }

    pub fn setNoDelay(self: *MockStack, _: u16, _: bool) void {
        self.nodelay_set = true;
    }

    pub fn setKeepalive(self: *MockStack, _: u16, _: bool) void {
        self.keepalive_set = true;
    }

    pub fn setLinger(self: *MockStack, _: u16, _: bool, _: u64) void {
        self.linger_set = true;
    }

    pub fn shutdownWrite(self: *MockStack, _: u16) void {
        self.shutdown_write_called = true;
    }

    pub fn shutdownRead(self: *MockStack, _: u16) void {
        self.shutdown_read_called = true;
    }

    pub fn connState(self: *const MockStack, _: u16) ?tcp_connection.State {
        return self.conn_state;
    }

    pub fn udpBind(self: *MockStack, _: u16) ?u16 {
        return self.udp_bind_result;
    }

    pub fn udpClose(self: *MockStack, _: u16) void {
        self.udp_close_called = true;
    }

    pub fn udpConnect(_: *MockStack, _: u16, _: [4]u8, _: u16) void {}

    pub fn udpSendTo(self: *MockStack, _: u16, _: [4]u8, _: u16, _: []const u8) bool {
        return self.udp_send_result;
    }

    pub fn udpSend(self: *MockStack, _: u16, _: []const u8) bool {
        return self.udp_send_result;
    }

    pub fn udpRecv(_: *MockStack, _: u16) ?@import("transport/udp/endpoint.zig").Datagram {
        return null;
    }

    pub fn hasReadableData(self: *const MockStack, _: u16) bool {
        return self.has_readable_data;
    }

    pub fn canWrite(self: *const MockStack, _: u16) bool {
        return self.can_write;
    }

    pub fn udpAvailable(self: *const MockStack, _: u16) usize {
        return self.udp_available_val;
    }
};
