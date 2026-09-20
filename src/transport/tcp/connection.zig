// TCP Connection: full-featured TCP socket combining Sender + Receiver + state machine.
//
// This module integrates all TCP sub-components:
// - State machine (SYN/ESTABLISHED/FIN/etc.)
// - Sender (segmentation, retransmission, RTT, congestion)
// - Receiver (in-order delivery, OOO reassembly, window management)
// - Timer (retransmit, delayed ACK, TIME-WAIT)
//
// Sans-IO: produces Output actions for the caller to serialize into packets.

const std = @import("std");
const tcp_header = @import("../../header/tcp.zig");
const endpoint_mod = @import("endpoint.zig");
const sender_mod = @import("sender.zig");
const receiver_mod = @import("receiver.zig");
const timer_mod = @import("timer.zig");
const options_mod = @import("options.zig");
const congestion_mod = @import("congestion.zig");
const rtt_mod = @import("rtt.zig");
const config_mod = @import("../../config.zig");
pub const Config = config_mod.Config;

const seqLt = endpoint_mod.seqLt;
const seqLte = endpoint_mod.seqLte;
const seqGt = endpoint_mod.seqGt;
const Sender = sender_mod.Sender;
const Receiver = receiver_mod.Receiver;
const Timer = timer_mod.Timer;

/// Connection state.
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

/// Output action produced by the Connection.
pub const Output = union(enum) {
    none,
    /// Send a TCP segment with the given parameters.
    send: Segment,
    /// Connection established (inform application).
    established,
    /// Connection closed (inform application).
    closed,
    /// Connection aborted due to error.
    aborted,
};

/// A TCP segment to be sent.
pub const Segment = struct {
    flags: tcp_header.Flags = .{},
    seq: u32 = 0,
    ack: u32 = 0,
    window: u16 = 0,
    /// Offset into the send buffer for payload data.
    payload_offset: usize = 0,
    /// Length of payload data.
    payload_len: usize = 0,
    /// Whether to include SYN options (MSS, WScale, SACK-permitted) in this segment.
    include_syn_options: bool = false,
};

/// Default Connection (uses Config.default — backwards-compatible).
pub const Connection = ConnectionWith(.{});

/// Configurable TCP Connection parameterized by comptime Config.
pub fn ConnectionWith(comptime cfg: Config) type {
    const SenderT = sender_mod.SenderWith(cfg);
    const ReceiverT = receiver_mod.ReceiverWith(cfg);
    const conn_send_buf_size = cfg.send_buf_size;

    return struct {
        const Self = @This();

        state: State = .closed,

        // Identification
        local_port: u16 = 0,
        remote_port: u16 = 0,

        // Sub-components
        sender: SenderT = .{},
        receiver: ReceiverT = .{},

        // Send buffer (application data waiting to be sent)
        send_buf: [conn_send_buf_size]u8 = undefined,
        send_buf_len: usize = 0,
        /// Bytes already passed to sender (but maybe not yet acked).
        send_buf_sent: usize = 0,

        // Close requested by application
        close_requested: bool = false,
        // Read direction shutdown (discard incoming data)
        read_shutdown: bool = false,
        // SO_LINGER: if set, linger_ms > 0 means wait up to linger_ms for data to drain.
        // linger_ms == 0 means abort immediately (RST).
        linger_enabled: bool = false,
        linger_ms: u64 = 0,
        linger_deadline: u64 = 0,

        // Keepalive
        keepalive_enabled: bool = false,
        keepalive_idle_ms: u64 = 75_000,
        keepalive_interval_ms: u64 = 75_000,
        keepalive_max_probes: u8 = 9,
        keepalive_probes_sent: u8 = 0,
        last_activity_ms: u64 = 0,

        // Timestamps
        timestamps_enabled: bool = false,
        ts_recent: u32 = 0,
        ts_last_ack_sent: u32 = 0,
        /// Timestamp of last ts_recent update (for PAWS 24-day invalidation).
        ts_recent_age: u64 = 0,

        // ECN (Explicit Congestion Notification, RFC 3168)
        ecn_enabled: bool = false,
        /// Whether we need to send CWR (we received ECE from peer)
        ecn_cwr_pending: bool = false,
        /// Whether we've received CE and need to signal ECE
        ecn_ece_pending: bool = false,

        // Negotiated options
        mss: u16 = cfg.default_mss,
        /// Send window scale (peer's shift count, applied to received window)
        snd_wscale: u4 = 0,
        /// Receive window scale (our shift count, applied to advertised window)
        rcv_wscale: u4 = 0,
        /// Whether window scaling was negotiated
        wscale_enabled: bool = false,
        /// Our offered window scale (shift count we advertise in SYN/SYN-ACK)
        our_wscale: u4 = 7,

        /// Create a new connection and initiate active open (client side).
        pub fn connect(local_port: u16, remote_port: u16, isn: u32) Self {
            var conn = Self{
                .state = .syn_sent,
                .local_port = local_port,
                .remote_port = remote_port,
                .sender = SenderT.init(isn, cfg.default_mss),
            };
            conn.sender.syn_sent = false; // will be sent on first poll
            return conn;
        }

        /// Create a new connection in LISTEN state (server side).
        pub fn listen(local_port: u16) Self {
            return Self{
                .state = .listen,
                .local_port = local_port,
            };
        }

        /// Initialize a server-side connection from an inbound SYN (sets up sender state + retx entry).
        pub fn acceptFromSyn(local_port: u16, isn: u32, now_ms: u64, peer_opts: options_mod.NegotiatedOptions) Self {
            var conn = Self{
                .state = .listen,
                .local_port = local_port,
                .sender = SenderT.init(isn, cfg.default_mss),
            };
            conn.applyPeerOptions(peer_opts);
            conn.sender.syn_sent = true;
            conn.sender.snd_nxt = isn +% 1;
            conn.sender.snd_una = isn;
            conn.sender.retx_queue[0] = .{
                .seq = isn,
                .len = 1,
                .sent_at = now_ms,
                .is_syn = true,
            };
            conn.sender.retx_count = 1;
            return conn;
        }

        /// Write data to the send buffer. Returns number of bytes accepted.
        pub fn write(self: *Self, data: []const u8) usize {
            if (self.state != .established and self.state != .close_wait) return 0;
            const space = self.send_buf.len - self.send_buf_len;
            const copy_len = @min(data.len, space);
            @memcpy(self.send_buf[self.send_buf_len .. self.send_buf_len + copy_len], data[0..copy_len]);
            self.send_buf_len += copy_len;
            return copy_len;
        }

        /// Read data from the receive buffer.
        pub fn read(self: *Self, buf: []u8) usize {
            return self.receiver.read(buf);
        }

        /// Initiate close (both directions).
        /// If SO_LINGER is enabled with timeout=0, triggers immediate RST.
        pub fn close(self: *Self) void {
            self.close_requested = true;
        }

        /// Set SO_LINGER option.
        /// enabled=true, timeout_ms=0: abort (RST) on close.
        /// enabled=true, timeout_ms>0: wait up to timeout for data to drain.
        /// enabled=false: default graceful close (FIN).
        pub fn setLinger(self: *Self, enabled: bool, timeout_ms: u64) void {
            self.linger_enabled = enabled;
            self.linger_ms = timeout_ms;
        }

        /// Close with abort (RST). Used when linger timeout=0.
        pub fn abortClose(self: *Self) Output {
            self.state = .closed;
            return .{ .send = .{
                .flags = .{ .rst = true },
                .seq = self.sender.snd_nxt,
            } };
        }

        /// Shutdown write direction only (send FIN, continue receiving).
        pub fn shutdownWrite(self: *Self) void {
            self.close_requested = true;
        }

        /// Shutdown read direction only (discard incoming data).
        pub fn shutdownRead(self: *Self) void {
            self.read_shutdown = true;
        }

        /// Process an incoming TCP segment.
        pub fn onSegment(self: *Self, now_ms: u64, flags: tcp_header.Flags, seg_seq: u32, seg_ack: u32, seg_wnd: u16, payload: []const u8) Output {
            switch (self.state) {
                .closed => {
                    if (flags.rst) return .none;
                    return .{ .send = .{
                        .flags = .{ .rst = true, .ack = true },
                        .seq = seg_ack,
                        .ack = seg_seq +% @as(u32, @intCast(payload.len)) +% @as(u32, if (flags.syn) 1 else 0),
                    } };
                },
                .listen => {
                    return self.onSegmentListen(flags, seg_seq);
                },
                .syn_sent => {
                    return self.onSegmentSynSent(now_ms, flags, seg_seq, seg_ack, seg_wnd);
                },
                .syn_received => {
                    return self.onSegmentSynReceived(now_ms, flags, seg_seq, seg_ack, seg_wnd, payload);
                },
                .established => {
                    return self.onSegmentEstablished(now_ms, flags, seg_seq, seg_ack, seg_wnd, payload);
                },
                .fin_wait_1 => {
                    return self.onSegmentFinWait1(now_ms, flags, seg_seq, seg_ack, seg_wnd, payload);
                },
                .fin_wait_2 => {
                    return self.onSegmentFinWait2(now_ms, flags, seg_seq, payload);
                },
                .close_wait => {
                    // Process ACKs only
                    if (flags.ack) {
                        _ = self.sender.onAck(now_ms, seg_ack);
                    }
                    return .none;
                },
                .last_ack => {
                    if (flags.ack and seg_ack == self.sender.snd_nxt) {
                        self.state = .closed;
                        return .closed;
                    }
                    return .none;
                },
                .closing => {
                    if (flags.ack and seg_ack == self.sender.snd_nxt) {
                        self.state = .time_wait;
                        self.sender.timer.setTimeWait(now_ms);
                    }
                    return .none;
                },
                .time_wait => {
                    // Restart 2MSL timer on any segment
                    self.sender.timer.setTimeWait(now_ms);
                    return .none;
                },
            }
        }

        /// Poll for output (call periodically or when timer fires).
        pub fn poll(self: *Self, now_ms: u64) Output {
            switch (self.state) {
                .syn_sent => {
                    const action = self.sender.poll(now_ms, 0, false);
                    return self.senderActionToOutput(action);
                },
                .established, .close_wait => {
                    // SO_LINGER: if close requested with linger timeout=0, send RST immediately
                    if (self.close_requested and self.linger_enabled and self.linger_ms == 0) {
                        return self.abortClose();
                    }

                    // SO_LINGER: if close requested with linger timeout>0, check deadline
                    if (self.close_requested and self.linger_enabled and self.linger_ms > 0) {
                        if (self.linger_deadline == 0) {
                            self.linger_deadline = now_ms + self.linger_ms;
                        }
                        if (now_ms >= self.linger_deadline and self.send_buf_len > 0) {
                            return self.abortClose();
                        }
                    }

                    const pending = self.send_buf_len - self.send_buf_sent;
                    const has_fin = self.close_requested and pending == 0;

                    const action = self.sender.poll(now_ms, pending, has_fin);
                    switch (action) {
                        .send_data => |d| {
                            self.send_buf_sent += d.data_len;
                            self.last_activity_ms = now_ms;
                            self.keepalive_probes_sent = 0;
                            return .{ .send = .{
                                .flags = .{ .ack = true, .psh = true },
                                .seq = d.seq,
                                .ack = self.receiver.rcv_nxt,
                                .window = self.scaledWindow(),
                                .payload_offset = d.buf_offset,
                                .payload_len = d.data_len,
                            } };
                        },
                        .send_fin => |f| {
                            if (self.state == .established) {
                                self.state = .fin_wait_1;
                            } else {
                                self.state = .last_ack;
                            }
                            return .{ .send = .{
                                .flags = .{ .fin = true, .ack = true },
                                .seq = f.seq,
                                .ack = self.receiver.rcv_nxt,
                                .window = self.scaledWindow(),
                            } };
                        },
                        .send_syn => |s| {
                            return .{ .send = .{
                                .flags = .{ .syn = true },
                                .seq = s.seq,
                                .window = self.scaledWindow(),
                                .include_syn_options = true,
                            } };
                        },
                        .abort => {
                            self.state = .closed;
                            return .aborted;
                        },
                        .none => {},
                    }

                    // Check if we need to send an ACK (delayed or immediate)
                    if (self.receiver.consumeAckNeeded()) {
                        return .{ .send = .{
                            .flags = .{ .ack = true },
                            .seq = self.sender.snd_nxt,
                            .ack = self.receiver.rcv_nxt,
                            .window = self.scaledWindow(),
                        } };
                    }

                    // Keepalive: if idle for too long, send probe
                    if (self.keepalive_enabled and self.sender.flight_size == 0 and pending == 0) {
                        const idle_threshold = if (self.keepalive_probes_sent == 0)
                            self.keepalive_idle_ms
                        else
                            self.keepalive_interval_ms;

                        if (now_ms >= self.last_activity_ms + idle_threshold) {
                            if (self.keepalive_probes_sent >= self.keepalive_max_probes) {
                                self.state = .closed;
                                return .aborted;
                            }
                            self.keepalive_probes_sent += 1;
                            self.last_activity_ms = now_ms;
                            // Keepalive probe: ACK with seq = snd_nxt - 1
                            return .{ .send = .{
                                .flags = .{ .ack = true },
                                .seq = self.sender.snd_nxt -% 1,
                                .ack = self.receiver.rcv_nxt,
                                .window = self.scaledWindow(),
                            } };
                        }
                    }

                    return .none;
                },
                .time_wait => {
                    if (self.sender.timer.shouldFire(now_ms)) {
                        self.state = .closed;
                        return .closed;
                    }
                    return .none;
                },
                else => return .none,
            }
        }

        /// Get the next time poll() should be called.
        pub fn nextPollAt(self: *const Self) ?u64 {
            return self.sender.nextPollAt();
        }

        /// Consume acked data from send buffer.
        pub fn consumeAcked(self: *Self, acked_bytes: usize) void {
            if (acked_bytes == 0) return;
            if (acked_bytes >= self.send_buf_len) {
                self.send_buf_len = 0;
                self.send_buf_sent = 0;
            } else {
                // Shift buffer
                std.mem.copyForwards(u8, self.send_buf[0 .. self.send_buf_len - acked_bytes], self.send_buf[acked_bytes..self.send_buf_len]);
                self.send_buf_len -= acked_bytes;
                if (self.send_buf_sent >= acked_bytes) {
                    self.send_buf_sent -= acked_bytes;
                } else {
                    self.send_buf_sent = 0;
                }
            }
        }

        // -- State-specific handlers --

        fn onSegmentListen(self: *Self, flags: tcp_header.Flags, seg_seq: u32) Output {
            if (flags.rst) return .none;
            if (!flags.syn) return .none;

            // Received SYN: init receiver, transition to SYN_RECEIVED
            self.receiver = ReceiverT.init(seg_seq, 65535);
            self.state = .syn_received;

            // Send SYN+ACK (with options)
            return .{ .send = .{
                .flags = .{ .syn = true, .ack = true },
                .seq = self.sender.iss,
                .ack = self.receiver.rcv_nxt,
                .window = self.scaledWindow(),
                .include_syn_options = true,
            } };
        }

        fn onSegmentSynSent(self: *Self, now_ms: u64, flags: tcp_header.Flags, seg_seq: u32, seg_ack: u32, seg_wnd: u16) Output {
            if (flags.rst) {
                if (flags.ack) {
                    self.state = .closed;
                    return .aborted;
                }
                return .none;
            }

            if (flags.syn and flags.ack) {
                // SYN+ACK: validate ACK covers our SYN
                const data_acked = self.sender.onAck(now_ms, seg_ack);
                _ = data_acked;

                if (!self.sender.syn_acked) {
                    // Invalid ACK
                    return .{ .send = .{ .flags = .{ .rst = true }, .seq = seg_ack } };
                }

                // Init receiver with peer's ISN
                self.receiver = ReceiverT.init(seg_seq, 65535);
                self.sender.setRemoteWindow(self.applyRecvWscale(seg_wnd));
                self.state = .established;

                // Send ACK
                return .{ .send = .{
                    .flags = .{ .ack = true },
                    .seq = self.sender.snd_nxt,
                    .ack = self.receiver.rcv_nxt,
                    .window = self.scaledWindow(),
                } };
            }

            if (flags.syn) {
                // Simultaneous open
                self.receiver = ReceiverT.init(seg_seq, 65535);
                self.state = .syn_received;
                return .{ .send = .{
                    .flags = .{ .syn = true, .ack = true },
                    .seq = self.sender.iss,
                    .ack = self.receiver.rcv_nxt,
                    .window = self.scaledWindow(),
                    .include_syn_options = true,
                } };
            }

            return .none;
        }

        fn onSegmentSynReceived(self: *Self, now_ms: u64, flags: tcp_header.Flags, seg_seq: u32, seg_ack: u32, seg_wnd: u16, payload: []const u8) Output {
            if (flags.rst) {
                self.state = .closed;
                return .aborted;
            }

            if (flags.ack) {
                // ACK of our SYN+ACK
                _ = self.sender.onAck(now_ms, seg_ack);
                if (self.sender.syn_acked) {
                    self.sender.setRemoteWindow(self.applyRecvWscale(seg_wnd));
                    self.state = .established;

                    // If this ACK also carries data, process it now
                    if (payload.len > 0) {
                        _ = self.receiver.onSegment(seg_seq, payload);
                    }

                    return .established;
                }
            }
            return .none;
        }

        fn onSegmentEstablished(self: *Self, now_ms: u64, flags: tcp_header.Flags, seg_seq: u32, seg_ack: u32, seg_wnd: u16, payload: []const u8) Output {
            if (flags.rst) {
                self.state = .closed;
                return .aborted;
            }

            // Reset keepalive on any received segment
            self.last_activity_ms = now_ms;
            self.keepalive_probes_sent = 0;

            // ECN: peer signals congestion via ECE flag
            if (self.ecn_enabled and flags.ece) {
                self.sender.congestion.onEcnCe();
                self.ecn_cwr_pending = true;
            }

            // ECN: if peer sent CWR, stop sending ECE
            if (flags.cwr) {
                self.ecn_ece_pending = false;
            }

            // Process ACK
            if (flags.ack) {
                const acked = self.sender.onAck(now_ms, seg_ack);
                self.sender.setRemoteWindow(self.applyRecvWscale(seg_wnd));
                self.consumeAcked(acked);
            }

            // Process data (discard if read direction is shut down)
            if (payload.len > 0 and !self.read_shutdown) {
                _ = self.receiver.onSegment(seg_seq, payload);
            }

            // Process FIN
            if (flags.fin) {
                self.receiver.onFin(seg_seq +% @as(u32, @intCast(payload.len)));
                self.state = .close_wait;
                // Immediate ACK for FIN
                return .{ .send = .{
                    .flags = .{ .ack = true },
                    .seq = self.sender.snd_nxt,
                    .ack = self.receiver.rcv_nxt,
                    .window = self.scaledWindow(),
                } };
            }

            return .none;
        }

        fn onSegmentFinWait1(self: *Self, now_ms: u64, flags: tcp_header.Flags, seg_seq: u32, seg_ack: u32, seg_wnd: u16, payload: []const u8) Output {
            if (flags.rst) {
                self.state = .closed;
                return .aborted;
            }

            if (flags.ack) {
                _ = self.sender.onAck(now_ms, seg_ack);
                self.sender.setRemoteWindow(self.applyRecvWscale(seg_wnd));
            }

            // Process data
            if (payload.len > 0) {
                _ = self.receiver.onSegment(seg_seq, payload);
            }

            if (flags.fin) {
                self.receiver.onFin(seg_seq +% @as(u32, @intCast(payload.len)));
                if (flags.ack and self.sender.fin_acked) {
                    // FIN+ACK: straight to TIME_WAIT
                    self.state = .time_wait;
                    self.sender.timer.setTimeWait(now_ms);
                } else {
                    // Simultaneous close
                    self.state = .closing;
                }
                return .{ .send = .{
                    .flags = .{ .ack = true },
                    .seq = self.sender.snd_nxt,
                    .ack = self.receiver.rcv_nxt,
                    .window = self.scaledWindow(),
                } };
            }

            if (flags.ack and self.sender.fin_acked) {
                self.state = .fin_wait_2;
            }

            return .none;
        }

        fn onSegmentFinWait2(self: *Self, now_ms: u64, flags: tcp_header.Flags, seg_seq: u32, payload: []const u8) Output {
            _ = now_ms;
            if (payload.len > 0) {
                _ = self.receiver.onSegment(seg_seq, payload);
            }

            if (flags.fin) {
                self.receiver.onFin(seg_seq +% @as(u32, @intCast(payload.len)));
                self.state = .time_wait;
                self.sender.timer.setTimeWait(0);
                return .{ .send = .{
                    .flags = .{ .ack = true },
                    .seq = self.sender.snd_nxt,
                    .ack = self.receiver.rcv_nxt,
                    .window = self.scaledWindow(),
                } };
            }
            return .none;
        }

        fn senderActionToOutput(self: *Self, action: sender_mod.EmitAction) Output {
            switch (action) {
                .send_syn => |s| {
                    return .{ .send = .{
                        .flags = .{ .syn = true },
                        .seq = s.seq,
                        .window = self.scaledWindow(),
                        .include_syn_options = true,
                    } };
                },
                .send_data => |d| {
                    self.send_buf_sent += d.data_len;
                    return .{ .send = .{
                        .flags = .{ .ack = true, .psh = true },
                        .seq = d.seq,
                        .ack = self.receiver.rcv_nxt,
                        .window = self.scaledWindow(),
                        .payload_offset = d.buf_offset,
                        .payload_len = d.data_len,
                    } };
                },
                .send_fin => |f| {
                    return .{ .send = .{
                        .flags = .{ .fin = true, .ack = true },
                        .seq = f.seq,
                        .ack = self.receiver.rcv_nxt,
                        .window = self.scaledWindow(),
                    } };
                },
                .abort => {
                    self.state = .closed;
                    return .aborted;
                },
                .none => return .none,
            }
        }

        /// Apply ECN flags to an outgoing segment's flags.
        pub fn applyEcnFlags(self: *Self, flags: tcp_header.Flags) tcp_header.Flags {
            if (!self.ecn_enabled) return flags;
            var f = flags;
            if (self.ecn_ece_pending) f.ece = true;
            if (self.ecn_cwr_pending) {
                f.cwr = true;
                self.ecn_cwr_pending = false;
            }
            return f;
        }

        /// Apply peer's SYN/SYN-ACK options to this connection.
        /// Called by the stack layer when it parses TCP options from a SYN or SYN-ACK.
        pub fn applyPeerOptions(self: *Self, opts: options_mod.NegotiatedOptions) void {
            // MSS
            if (opts.mss > 0) {
                self.mss = opts.mss;
                self.sender.setMss(opts.mss);
            }

            // Window Scale: enable if peer included WScale option in SYN (even with shift=0)
            if (opts.window_scale_offered) {
                self.snd_wscale = @intCast(opts.window_scale);
                self.rcv_wscale = self.our_wscale;
                self.wscale_enabled = true;
            }

            // SACK permitted
            if (opts.sack_permitted) {
                // Already handled by receiver — just note it's available
            }

            // Timestamps (RFC 7323)
            if (opts.timestamps_enabled) {
                self.timestamps_enabled = true;
            }
        }

        /// PAWS (Protection Against Wrapped Sequences) check.
        /// Returns true if the segment should be REJECTED (TSval is too old).
        /// RFC 7323 Section 4.2: reject if TSval < ts_recent AND ts_recent is still valid.
        /// ts_recent expires after 24 days (invalidation window for wrapped timestamps).
        /// RST segments are exempt from PAWS.
        pub fn pawsReject(self: *const Self, now_ms: u64, tsval: u32, is_rst: bool) bool {
            if (!self.timestamps_enabled) return false;
            if (is_rst) return false;
            if (self.ts_recent == 0) return false;

            // RFC 7323: ts_recent is invalidated after 24 days
            const paws_idle_max: u64 = 24 * 24 * 60 * 60 * 1000; // 24 days in ms
            if (now_ms > self.ts_recent_age + paws_idle_max) return false;

            // Timestamp comparison uses signed arithmetic (like sequence numbers)
            const diff = @as(i32, @bitCast(tsval -% self.ts_recent));
            return diff < 0;
        }

        /// Process incoming timestamp option from a data segment.
        /// Updates ts_recent for echo and provides RTT sample.
        /// Caller must have already passed PAWS check before calling this.
        pub fn processTimestamp(self: *Self, now_ms: u64, tsval: u32, tsecr: u32) void {
            if (!self.timestamps_enabled) return;

            // Update ts_recent only if TSval >= ts_recent (PAWS-safe update)
            const diff = @as(i32, @bitCast(tsval -% self.ts_recent));
            if (diff >= 0) {
                self.ts_recent = tsval;
                self.ts_recent_age = now_ms;
            }

            // RTT from echoed timestamp. TSecr is what the peer echoed of our
            // TSval, which is the clock truncated to 32 bits, so the sample
            // has to be taken in that same 32-bit space: subtracting it from
            // the full clock gives the age of the machine once that clock
            // passes 2^32 ms (49.7 days of uptime), not the round trip.
            if (tsecr != 0) {
                const sample = self.currentTsval(now_ms) -% tsecr;
                // A round trip longer than the maximum RTO is not a round trip
                // we can learn anything from: a stale echo, a peer with a
                // different idea of the clock, or our own wrap.
                if (sample > 0 and sample <= rtt_mod.max_sample_ms) {
                    self.sender.rtt.update(sample);
                }
            }
        }

        /// Get current TSval to send (millisecond clock truncated to 32 bits).
        pub fn currentTsval(self: *const Self, now_ms: u64) u32 {
            _ = self;
            return @truncate(now_ms);
        }

        /// Get TSecr to echo back (the most recent TSval received from peer).
        pub fn currentTsecr(self: *const Self) u32 {
            return self.ts_recent;
        }

        /// Apply send-side window scale to a received window value.
        fn applyRecvWscale(self: *const Self, seg_wnd: u16) u32 {
            if (!self.wscale_enabled) return @as(u32, seg_wnd);
            return @as(u32, seg_wnd) << self.snd_wscale;
        }

        /// Get our advertised window, scaled down for the wire (16-bit TCP header field).
        /// Uses the raw u32 window and right-shifts by our advertised scale factor.
        pub fn scaledWindow(self: *const Self) u16 {
            const raw = self.receiver.windowRaw();
            if (!self.wscale_enabled) return @intCast(@min(raw, 65535));
            return @intCast(@min(raw >> self.rcv_wscale, 65535));
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Connection: client-server handshake" {
    // Client side
    var client = Connection.connect(5000, 80, 1000);
    try testing.expectEqual(State.syn_sent, client.state);

    // Client polls → sends SYN
    const syn_out = client.poll(0);
    switch (syn_out) {
        .send => |seg| {
            try testing.expect(seg.flags.syn);
            try testing.expectEqual(@as(u32, 1000), seg.seq);
        },
        else => return error.TestUnexpectedResult,
    }

    // Server side
    var server = Connection.listen(80);
    try testing.expectEqual(State.listen, server.state);

    // Server receives SYN → sends SYN+ACK
    server.sender = Sender.init(2000, 1460);
    const syn_ack_out = server.onSegment(10, .{ .syn = true }, 1000, 0, 65535, &.{});
    try testing.expectEqual(State.syn_received, server.state);
    switch (syn_ack_out) {
        .send => |seg| {
            try testing.expect(seg.flags.syn);
            try testing.expect(seg.flags.ack);
            try testing.expectEqual(@as(u32, 1001), seg.ack);
        },
        else => return error.TestUnexpectedResult,
    }

    // Client receives SYN+ACK → sends ACK, becomes ESTABLISHED
    const ack_out = client.onSegment(20, .{ .syn = true, .ack = true }, 2000, 1001, 65535, &.{});
    try testing.expectEqual(State.established, client.state);
    switch (ack_out) {
        .send => |seg| {
            try testing.expect(seg.flags.ack);
            try testing.expectEqual(@as(u32, 2001), seg.ack);
        },
        else => return error.TestUnexpectedResult,
    }

    // Server receives ACK → becomes ESTABLISHED
    // The server's sender needs to know that SYN was sent and the ack should match ISS+1=2001
    server.sender.syn_sent = true;
    server.sender.snd_nxt = 2001;
    server.sender.snd_una = 2000;
    // Enqueue the SYN in retx queue so onAck can dequeue it
    server.sender.retx_queue[0] = .{
        .seq = 2000,
        .len = 1,
        .sent_at = 10,
        .is_syn = true,
    };
    server.sender.retx_count = 1;
    const estab_out = server.onSegment(30, .{ .ack = true }, 1001, 2001, 65535, &.{});
    try testing.expectEqual(State.established, server.state);
    switch (estab_out) {
        .established => {},
        else => return error.TestUnexpectedResult,
    }
}

test "Connection: data transfer" {
    // Set up a pre-established client
    var conn = Connection{
        .state = .established,
        .sender = Sender.init(1000, 100),
        .receiver = Receiver.init(2000, 65535),
    };
    conn.sender.syn_sent = true;
    conn.sender.syn_acked = true;
    conn.sender.snd_nxt = 1001;
    conn.sender.snd_una = 1001;
    conn.sender.nagle_enabled = false;

    // Write data
    const written = conn.write("hello world!");
    try testing.expectEqual(@as(usize, 12), written);

    // Poll → should emit data segment
    const out = conn.poll(100);
    switch (out) {
        .send => |seg| {
            try testing.expect(seg.flags.ack);
            try testing.expectEqual(@as(u32, 1001), seg.seq);
            try testing.expectEqual(@as(usize, 12), seg.payload_len);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "Connection: receive data" {
    var conn = Connection{
        .state = .established,
        .sender = Sender.init(1000, 1460),
        .receiver = Receiver.init(2000, 65535),
    };
    conn.sender.syn_sent = true;
    conn.sender.syn_acked = true;
    conn.sender.snd_nxt = 1001;
    conn.sender.snd_una = 1001;

    // Receive data from remote
    _ = conn.onSegment(100, .{ .ack = true }, 2001, 1001, 65535, "hello");

    // Read from application
    var buf: [10]u8 = undefined;
    const n = conn.read(&buf);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualSlices(u8, "hello", buf[0..5]);
}

test "Connection: close sequence" {
    var conn = Connection{
        .state = .established,
        .sender = Sender.init(1000, 1460),
        .receiver = Receiver.init(2000, 65535),
    };
    conn.sender.syn_sent = true;
    conn.sender.syn_acked = true;
    conn.sender.snd_nxt = 1001;
    conn.sender.snd_una = 1001;

    // Application requests close
    conn.close();

    // Poll → should send FIN
    const out = conn.poll(100);
    switch (out) {
        .send => |seg| {
            try testing.expect(seg.flags.fin);
            try testing.expect(seg.flags.ack);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(State.fin_wait_1, conn.state);
}

test "Connection: window scaling negotiation" {
    var client = Connection.connect(5000, 80, 1000);
    client.our_wscale = 7;

    // Client polls → SYN (with options flag)
    const syn_out = client.poll(0);
    switch (syn_out) {
        .send => |seg| {
            try testing.expect(seg.include_syn_options);
        },
        else => return error.TestUnexpectedResult,
    }

    // Simulate receiving SYN-ACK with WScale=5 from peer
    const peer_opts = options_mod.NegotiatedOptions{
        .mss = 1400,
        .window_scale = 5,
        .window_scale_offered = true,
        .sack_permitted = true,
        .timestamps_enabled = false,
    };
    client.applyPeerOptions(peer_opts);

    try testing.expect(client.wscale_enabled);
    try testing.expectEqual(@as(u4, 5), client.snd_wscale);
    try testing.expectEqual(@as(u4, 7), client.rcv_wscale);
    try testing.expectEqual(@as(u16, 1400), client.mss);

    // Test scaling: peer's window 1000 with scale 5 → 1000 << 5 = 32000
    const effective_wnd = client.applyRecvWscale(1000);
    try testing.expectEqual(@as(u32, 32000), effective_wnd);
}

test "Connection: window scaling disabled if peer doesn't offer" {
    var client = Connection.connect(5000, 80, 1000);
    client.our_wscale = 7;

    // Peer sends SYN-ACK without WScale option
    const peer_opts = options_mod.NegotiatedOptions{
        .mss = 1460,
        .window_scale = 0,
        .sack_permitted = false,
        .timestamps_enabled = false,
    };
    client.applyPeerOptions(peer_opts);

    try testing.expect(!client.wscale_enabled);
    // Without scaling, window is just the 16-bit value
    const effective_wnd = client.applyRecvWscale(1000);
    try testing.expectEqual(@as(u32, 1000), effective_wnd);
}

test "Connection: timestamps negotiation and processing" {
    var conn = Connection.connect(5000, 80, 1000);

    // Peer offers timestamps
    conn.applyPeerOptions(.{
        .mss = 1460,
        .window_scale = 0,
        .sack_permitted = false,
        .timestamps_enabled = true,
    });
    try testing.expect(conn.timestamps_enabled);

    // Process incoming timestamp: peer sent TSval=500 at our time=600
    conn.processTimestamp(600, 500, 100);
    try testing.expectEqual(@as(u32, 500), conn.ts_recent);

    // Our TSecr should echo the most recent TSval from peer
    try testing.expectEqual(@as(u32, 500), conn.currentTsecr());

    // Our TSval is based on current time
    try testing.expectEqual(@as(u32, 700), conn.currentTsval(700));
}

test "Connection: timestamps disabled when peer doesn't offer" {
    var conn = Connection.connect(5000, 80, 1000);

    conn.applyPeerOptions(.{
        .mss = 1460,
        .window_scale = 0,
        .sack_permitted = false,
        .timestamps_enabled = false,
    });
    try testing.expect(!conn.timestamps_enabled);

    // processTimestamp should be a no-op when disabled
    conn.processTimestamp(100, 999, 50);
    try testing.expectEqual(@as(u32, 0), conn.ts_recent);
}

test "Connection: scaledWindow applies shift on wire" {
    var conn = Connection{
        .state = .established,
        .sender = Sender.init(1000, 1460),
        .receiver = Receiver.init(2000, 65535),
    };
    conn.sender.syn_sent = true;
    conn.sender.syn_acked = true;
    conn.sender.snd_nxt = 1001;
    conn.sender.snd_una = 1001;

    // Without scaling: window = raw (capped at 65535)
    conn.wscale_enabled = false;
    const unscaled = conn.scaledWindow();
    try testing.expect(unscaled > 0);
    try testing.expect(unscaled <= 65535);

    // With scaling (rcv_wscale=7): wire value = raw >> 7
    conn.wscale_enabled = true;
    conn.rcv_wscale = 7;
    const scaled = conn.scaledWindow();
    // Scaled should be raw >> 7, which is much smaller
    try testing.expect(scaled < unscaled);
    // Verify: scaled << 7 should be ≤ raw window (due to truncation)
    const reconstructed: u32 = @as(u32, scaled) << 7;
    const raw_window = conn.receiver.windowRaw();
    try testing.expect(reconstructed <= raw_window);
}

test "Connection: applyRecvWscale scales peer window" {
    var conn = Connection.connect(5000, 80, 1000);

    // Enable scaling with snd_wscale=5 (peer's shift)
    conn.wscale_enabled = true;
    conn.snd_wscale = 5;

    // Peer advertises window=512 on wire → effective = 512 << 5 = 16384
    const effective = conn.applyRecvWscale(512);
    try testing.expectEqual(@as(u32, 16384), effective);

    // Peer advertises window=65535 → effective = 65535 << 5 = 2097120
    const large = conn.applyRecvWscale(65535);
    try testing.expectEqual(@as(u32, 2097120), large);
}

test "Connection: window scaling in data segment output" {
    var conn = Connection{
        .state = .established,
        .sender = Sender.init(1000, 100),
        .receiver = Receiver.init(2000, 65535),
    };
    conn.sender.syn_sent = true;
    conn.sender.syn_acked = true;
    conn.sender.snd_nxt = 1001;
    conn.sender.snd_una = 1001;
    conn.sender.nagle_enabled = false;
    conn.wscale_enabled = true;
    conn.rcv_wscale = 7;

    // Write and send data
    _ = conn.write("test data");
    const out = conn.poll(100);
    switch (out) {
        .send => |seg| {
            // Wire window should be scaled (raw >> 7)
            const expected_scaled = conn.scaledWindow();
            try testing.expectEqual(expected_scaled, seg.window);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "Connection: window scaling full round-trip" {
    // Client: our_wscale=7, peer offers wscale=5
    var client = Connection.connect(5000, 80, 1000);
    client.our_wscale = 7;

    // Simulate peer SYN-ACK with WScale=5
    client.applyPeerOptions(.{
        .mss = 1460,
        .window_scale = 5,
        .window_scale_offered = true,
        .sack_permitted = false,
        .timestamps_enabled = false,
    });

    try testing.expect(client.wscale_enabled);
    try testing.expectEqual(@as(u4, 5), client.snd_wscale);
    try testing.expectEqual(@as(u4, 7), client.rcv_wscale);

    // When we receive peer's wire window=1000, effective = 1000 << 5 = 32000
    const peer_effective = client.applyRecvWscale(1000);
    try testing.expectEqual(@as(u32, 32000), peer_effective);

    // When we advertise our window, it's raw >> 7
    const our_wire = client.scaledWindow();
    const our_raw = client.receiver.windowRaw();
    // our_wire << 7 should be ≤ our_raw (due to truncation)
    try testing.expect(@as(u32, our_wire) << 7 <= our_raw);
}

test "Connection: the echoed timestamp is read on the clock that wrote it" {
    // A machine up for 98 days: the millisecond clock is past 2^32, and the
    // TSval on the wire is its low 32 bits. Subtracting that from the full
    // clock gave the age of the machine as the round trip, which the RTT
    // estimator then tried to turn into an RTO and overflowed on.
    const uptime_ms: u64 = 98 * 24 * 60 * 60 * 1000;
    var conn = Connection.connect(5000, 80, 1000);
    conn.timestamps_enabled = true;

    const sent_at = uptime_ms - 120;
    conn.processTimestamp(uptime_ms, 7777, conn.currentTsval(sent_at));

    try testing.expectEqual(@as(u32, 120), conn.sender.rtt.srtt.?);
    try testing.expect(conn.sender.rtt.rto <= 60_000);

    // And across the wrap itself: the echo was written just before the clock
    // passed 2^32, the ACK arrives just after.
    var wrapped = Connection.connect(5001, 80, 1000);
    wrapped.timestamps_enabled = true;
    const at_wrap: u64 = @as(u64, 1) << 32;
    wrapped.processTimestamp(at_wrap + 30, 8888, wrapped.currentTsval(at_wrap - 90));
    try testing.expectEqual(@as(u32, 120), wrapped.sender.rtt.srtt.?);
}

test "Connection: an echo nothing could have measured is left alone" {
    var conn = Connection.connect(5000, 80, 1000);
    conn.timestamps_enabled = true;
    conn.processTimestamp(1_000_000, 100, conn.currentTsval(500));
    // Older than any round trip worth believing: no sample taken.
    try testing.expect(conn.sender.rtt.srtt == null);
    try testing.expectEqual(@as(u32, 1000), conn.sender.rtt.rto);
}

test "Connection: PAWS rejects old timestamp" {
    var conn = Connection.connect(5000, 80, 1000);
    conn.timestamps_enabled = true;
    conn.ts_recent = 500;
    conn.ts_recent_age = 1000;

    // TSval=400 is older than ts_recent=500 → PAWS reject
    try testing.expect(conn.pawsReject(2000, 400, false));

    // TSval=600 is newer → allow
    try testing.expect(!conn.pawsReject(2000, 600, false));

    // TSval=500 (same) → allow (diff == 0, not < 0)
    try testing.expect(!conn.pawsReject(2000, 500, false));
}

test "Connection: PAWS allows RST regardless of timestamp" {
    var conn = Connection.connect(5000, 80, 1000);
    conn.timestamps_enabled = true;
    conn.ts_recent = 500;
    conn.ts_recent_age = 1000;

    // Even old TSval should be allowed if RST
    try testing.expect(!conn.pawsReject(2000, 100, true));
}

test "Connection: PAWS inactive when timestamps disabled" {
    var conn = Connection.connect(5000, 80, 1000);
    conn.timestamps_enabled = false;
    conn.ts_recent = 500;

    // Should never reject without timestamps
    try testing.expect(!conn.pawsReject(2000, 100, false));
}

test "Connection: PAWS inactive when ts_recent is zero" {
    var conn = Connection.connect(5000, 80, 1000);
    conn.timestamps_enabled = true;
    conn.ts_recent = 0;

    // No reference point → no PAWS rejection
    try testing.expect(!conn.pawsReject(2000, 100, false));
}

test "Connection: PAWS ts_recent expires after 24 days" {
    var conn = Connection.connect(5000, 80, 1000);
    conn.timestamps_enabled = true;
    conn.ts_recent = 500;
    conn.ts_recent_age = 1000;

    // 24 days + 1ms later: PAWS should not reject (ts_recent invalidated)
    const paws_idle_max: u64 = 24 * 24 * 60 * 60 * 1000 + 1;
    try testing.expect(!conn.pawsReject(1000 + paws_idle_max, 100, false));
}

test "Connection: processTimestamp updates ts_recent only forward" {
    var conn = Connection.connect(5000, 80, 1000);
    conn.timestamps_enabled = true;

    // First timestamp establishes ts_recent
    conn.processTimestamp(100, 500, 0);
    try testing.expectEqual(@as(u32, 500), conn.ts_recent);

    // Newer timestamp updates
    conn.processTimestamp(200, 600, 0);
    try testing.expectEqual(@as(u32, 600), conn.ts_recent);

    // Older timestamp does NOT update ts_recent
    conn.processTimestamp(300, 550, 0);
    try testing.expectEqual(@as(u32, 600), conn.ts_recent);
}

test "Connection: processTimestamp RTT measurement via TSecr" {
    var conn = Connection{
        .state = .established,
        .sender = Sender.init(1000, 1460),
        .receiver = Receiver.init(2000, 65535),
    };
    conn.timestamps_enabled = true;

    // Simulate: we sent TSval=100 at time 100, peer echoes TSecr=100 at time 200
    conn.processTimestamp(200, 500, 100);

    // RTT sample = 200 - 100 = 100ms → rtt estimator should have been updated
    try testing.expect(conn.sender.rtt.srtt != null);
}

test "Connection: PAWS wrapping arithmetic" {
    var conn = Connection.connect(5000, 80, 1000);
    conn.timestamps_enabled = true;
    conn.ts_recent = 0xFFFFFF00; // near wrap
    conn.ts_recent_age = 1000;

    // TSval wraps: 0x00000010 is "after" 0xFFFFFF00 in modular arithmetic
    try testing.expect(!conn.pawsReject(2000, 0x00000010, false));

    // TSval = 0xFFFFFE00 is "before" 0xFFFFFF00
    try testing.expect(conn.pawsReject(2000, 0xFFFFFE00, false));
}

const test_cfg = Config{};

fn makeEstablished() Connection {
    var conn = Connection.connect(5000, 80, 1000);
    conn.state = .established;
    conn.sender.syn_sent = true;
    conn.sender.syn_acked = true;
    conn.sender.snd_nxt = 1001;
    conn.sender.snd_una = 1001;
    conn.last_activity_ms = 0;
    conn.receiver = receiver_mod.ReceiverWith(test_cfg).init(2000, @intCast(@min(test_cfg.recv_buf_size, 65535)));
    return conn;
}

test "Connection: keepalive sends probe after idle" {
    var conn = makeEstablished();
    conn.keepalive_enabled = true;
    conn.keepalive_idle_ms = 100;
    conn.keepalive_interval_ms = 50;
    conn.keepalive_max_probes = 3;

    // Before idle threshold: no probe
    const out1 = conn.poll(99);
    try testing.expectEqual(Output.none, out1);

    // At idle threshold: first probe
    const out2 = conn.poll(100);
    switch (out2) {
        .send => |seg| {
            try testing.expect(seg.flags.ack);
            try testing.expectEqual(@as(u32, 1000), seg.seq); // snd_nxt - 1
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(u8, 1), conn.keepalive_probes_sent);
}

test "Connection: keepalive resets on received segment" {
    var conn = makeEstablished();
    conn.keepalive_enabled = true;
    conn.keepalive_idle_ms = 100;
    conn.keepalive_max_probes = 3;

    // Trigger a probe
    _ = conn.poll(100);
    try testing.expectEqual(@as(u8, 1), conn.keepalive_probes_sent);

    // Receive an ACK — resets probes
    _ = conn.onSegment(150, .{ .ack = true }, 2000, 1001, 65535, &.{});
    try testing.expectEqual(@as(u8, 0), conn.keepalive_probes_sent);
}

test "Connection: keepalive aborts after max probes" {
    var conn = makeEstablished();
    conn.keepalive_enabled = true;
    conn.keepalive_idle_ms = 100;
    conn.keepalive_interval_ms = 50;
    conn.keepalive_max_probes = 2;

    // First probe at 100ms
    _ = conn.poll(100);
    try testing.expectEqual(@as(u8, 1), conn.keepalive_probes_sent);

    // Second probe at 150ms
    _ = conn.poll(150);
    try testing.expectEqual(@as(u8, 2), conn.keepalive_probes_sent);

    // Third attempt: max_probes exceeded → abort
    const out = conn.poll(200);
    try testing.expectEqual(Output.aborted, out);
    try testing.expectEqual(State.closed, conn.state);
}

test "Connection: linger timeout=0 sends RST on close" {
    var conn = makeEstablished();
    conn.setLinger(true, 0);
    conn.close();

    const out = conn.poll(10);
    switch (out) {
        .send => |seg| try testing.expect(seg.flags.rst),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(State.closed, conn.state);
}

test "Connection: linger timeout>0 aborts after deadline with unsent data" {
    var conn = makeEstablished();
    conn.setLinger(true, 100);

    // Write data to send buffer
    _ = conn.write("hello world");
    conn.close();

    // Before deadline: should try to send data, not RST
    const out1 = conn.poll(50);
    switch (out1) {
        .send => |seg| try testing.expect(!seg.flags.rst),
        else => {},
    }

    // Simulate that data hasn't been acked (send_buf_len > 0)
    // After deadline with unsent data: abort
    const out2 = conn.poll(200);
    switch (out2) {
        .send => |seg| try testing.expect(seg.flags.rst),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(State.closed, conn.state);
}

test "Connection: ECN ECE received reduces cwnd and sets CWR" {
    var conn = makeEstablished();
    conn.ecn_enabled = true;
    conn.sender.congestion = congestion_mod.Controller.init(.reno, test_cfg.default_mss);
    const cwnd_before = conn.sender.congestion.reno.cwnd;

    // Receive segment with ECE flag
    _ = conn.onSegment(10, .{ .ack = true, .ece = true }, 2000, 1001, 65535, &.{});

    // cwnd should be reduced
    try testing.expect(conn.sender.congestion.reno.cwnd < cwnd_before);
    // CWR should be pending
    try testing.expect(conn.ecn_cwr_pending);
}

test "Connection: ECN CWR flag applied to outgoing and clears pending" {
    var conn = makeEstablished();
    conn.ecn_enabled = true;
    conn.ecn_cwr_pending = true;

    const flags = conn.applyEcnFlags(.{ .ack = true });
    try testing.expect(flags.cwr);
    try testing.expect(!conn.ecn_cwr_pending);
}

test "Connection: ECN CWR received clears ECE pending" {
    var conn = makeEstablished();
    conn.ecn_enabled = true;
    conn.ecn_ece_pending = true;

    // Receive CWR from peer
    _ = conn.onSegment(10, .{ .ack = true, .cwr = true }, 2000, 1001, 65535, &.{});
    try testing.expect(!conn.ecn_ece_pending);
}
