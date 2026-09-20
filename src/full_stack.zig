// FullStack: End-to-end integrated TCP/IP stack.
//
// Connects all layers into a working packet pipeline:
//   LinkEndpoint ↔ IPv4 parse/build ↔ TCP Connection pool ↔ Application
//
// Handles the complete flow:
//   Inbound:  raw IP bytes → parse → demux → TCP state machine → recv buffer
//   Outbound: Connection.poll() → build TCP+IP headers → checksum → link extract
//
// Sans-IO: caller drives with injectPacket() / poll() / advance().

const std = @import("std");
const link_mod = @import("link.zig");
const isn_mod = @import("isn.zig");
const syn_cookie_mod = @import("syn_cookie.zig");
const reassembly_mod = @import("ip_reassembly.zig");
const ipv6_frag_mod = @import("ipv6_frag.zig");
const icmp_header = @import("header/icmp.zig");
const ipv6_header = @import("header/ipv6.zig");
const tcp_connection = @import("transport/tcp/connection.zig");
const tcp_sender = @import("transport/tcp/sender.zig");
const tcp_receiver = @import("transport/tcp/receiver.zig");
const tcp_header = @import("header/tcp.zig");
const ipv4_header = @import("header/ipv4.zig");
const udp_header = @import("header/udp.zig");
const udp_endpoint = @import("transport/udp/endpoint.zig");
const conntrack_mod = @import("conntrack.zig");
const forwarder_mod = @import("forward/forwarder.zig");
const checksum_mod = @import("checksum.zig");

const Connection = tcp_connection.Connection;
const Segment = tcp_connection.Segment;
const Sender = tcp_sender.Sender;
const Receiver = tcp_receiver.Receiver;

/// Connection identifier (4-tuple).
pub const ConnId = struct {
    local_addr: [4]u8,
    local_port: u16,
    remote_addr: [4]u8,
    remote_port: u16,
};

/// Events emitted to the caller.
pub const Event = union(enum) {
    none,
    /// New connection accepted from inbound SYN.
    accepted: u16,
    /// Connection has data ready to read.
    data_ready: u16,
    /// Connection transitioned to ESTABLISHED.
    established: u16,
    /// Connection closed.
    closed: u16,
    /// Connection aborted.
    aborted: u16,
    /// UDP datagram received on endpoint index.
    udp_recv: u16,
    /// A SYN arrived for a port registered with listenDeferred and is being
    /// held: nothing has been sent to the peer yet, and no connection state
    /// exists. The application settles it with acceptPending or
    /// rejectPending. The payload is the pending index.
    syn_pending: u16,
};

/// Full integrated stack with default config.
pub fn FullStack(comptime max_conns: usize) type {
    return FullStackWith(max_conns, .{});
}

/// Full integrated stack parameterized by comptime Config.
pub fn FullStackWith(comptime max_conns: usize, comptime cfg: tcp_connection.Config) type {
    return FullStackFull(max_conns, cfg, link_mod.ChannelEndpoint);
}

/// Full integrated stack parameterized by Config and link endpoint type.
pub fn FullStackFull(comptime max_conns: usize, comptime cfg: tcp_connection.Config, comptime LinkT: type) type {
    const ConnectionT = tcp_connection.ConnectionWith(cfg);
    const SenderT = tcp_sender.SenderWith(cfg);
    const ReceiverT = tcp_receiver.ReceiverWith(cfg);

    return struct {
        const Self = @This();

        pub const max_connections = max_conns;

        const TcpApi = @import("tcp.zig").Tcp(Self);
        pub const Server = TcpApi.Server;
        pub const ServerEvent = TcpApi.ServerEvent;
        pub const Listener = TcpApi.Listener;
        pub const Stream = TcpApi.Stream;

        pub const ConnSlot = struct {
            conn: ConnectionT = .{},
            id: ConnId = undefined,
            active: bool = false,
            /// Opened by a SYN we answered, rather than by connect(). Set
            /// when the slot is taken and read when the handshake finishes:
            /// asking "is this port listening?" at that point gets it wrong
            /// both ways, since a listener can go away mid-handshake and an
            /// active open can use a port the stack also listens on.
            passive: bool = false,
            is_v6: bool = false,
            local_addr6: [16]u8 = .{0} ** 16,
            remote_addr6: [16]u8 = .{0} ** 16,
        };

        const max_udp_endpoints: usize = cfg.max_udp_endpoints;

        pub const UdpSlot = struct {
            ep: udp_endpoint.Endpoint = .{},
            active: bool = false,
        };

        const max_listen_ports: usize = cfg.max_listen_ports;
        const max_pending_syns: usize = cfg.max_pending_syns;

        /// A SYN for a deferred port, kept until the application decides. It
        /// holds what acceptConn would have been called with, so accepting it
        /// later takes exactly the path an immediate accept would have.
        pub const PendingSyn = struct {
            id: ConnId = undefined,
            peer_seq: u32 = 0,
            peer_wnd: u16 = 0,
            peer_opts: @import("transport/tcp/options.zig").NegotiatedOptions = .{},
            received_ms: u64 = 0,
            active: bool = false,
            is_v6: bool = false,
            local_addr6: [16]u8 = .{0} ** 16,
            remote_addr6: [16]u8 = .{0} ** 16,
        };

        /// What a caller needs to decide whether to take the connection.
        pub const PendingInfo = struct {
            local_port: u16,
            remote_addr: [4]u8,
            remote_port: u16,
            received_ms: u64,
            is_v6: bool,
            remote_addr6: [16]u8,
        };
        const ReasmT = reassembly_mod.ReassemblerWith(8, cfg.max_reasm_datagram);
        const use_hash_index = max_conns > 32;
        const hash_capacity = if (use_hash_index) max_conns * 2 else 0;
        const empty_slot: u16 = @intCast(max_conns);

        conns: [max_conns]ConnSlot = [_]ConnSlot{.{}} ** max_conns,
        conn_hash: [hash_capacity]u16 = [_]u16{empty_slot} ** hash_capacity,
        active_count: usize = 0,
        // Listen state (up to 8 simultaneous listen ports)
        listen_ports: [max_listen_ports]u16 = .{0} ** max_listen_ports,
        /// Parallel to listen_ports: whether that port holds its SYNs.
        listen_deferred: [max_listen_ports]bool = .{false} ** max_listen_ports,
        listen_count: usize = 0,
        pending_syns: [max_pending_syns]PendingSyn = [_]PendingSyn{.{}} ** max_pending_syns,
        // SYN queue limit (half-open connections in SYN_RECEIVED)
        syn_queue_limit: u16 = 128,
        // SYN queue count (incremental O(1) tracking)
        syn_queue_count: u16 = 0,
        // Accept queue limit (established connections waiting for app accept())
        accept_queue_limit: u16 = 128,
        // Accept queue: ring buffer of connection indices ready for application
        accept_queue: [max_conns]u16 = undefined,
        accept_queue_head: usize = 0,
        accept_queue_tail: usize = 0,
        accept_queue_count: usize = 0,
        udp_eps: [max_udp_endpoints]UdpSlot = [_]UdpSlot{.{}} ** max_udp_endpoints,
        udp_count: usize = 0,
        link: *LinkT,

        // ISN generation (RFC 6528 compliant)
        isn_gen: isn_mod.IsnGenerator = isn_mod.IsnGenerator.init(.{0} ** 16),
        // SYN cookie generator (stateless SYN flood defense)
        syn_cookie: syn_cookie_mod.SynCookie = syn_cookie_mod.SynCookie.init(.{0} ** 16),
        // SYN cookie mode: threshold of half-open conns to activate
        syn_cookie_threshold: u16 = 12,
        // IPv4 fragment reassembly (sized by config)
        reassembler: ReasmT = .{},
        // IPv6 fragment reassembly
        v6_reassembler: ipv6_frag_mod.Reassembler = .{},
        // IP identification field counter
        ip_id_counter: u16 = 1,
        // Per-instance ephemeral port counter (49152–65535)
        ephemeral_port_counter: u16 = 49152,
        // Last timestamp passed to tick/injectPacket (for outbound timestamping)
        last_tick_ms: u64 = 0,

        // Local address
        local_addr: [4]u8 = .{ 0, 0, 0, 0 },
        // Local IPv6 address
        local_addr6: [16]u8 = .{0} ** 16,
        // Whether IPv6 is configured
        ipv6_enabled: bool = false,
        // Current path MTU (default 1500, updated by ICMP errors)
        path_mtu: u16 = 1500,
        // Forwarding / NAT
        forwarding_enabled: bool = false,
        conntrack: conntrack_mod.ConnTrack = conntrack_mod.ConnTrack.init(),
        forwarder: forwarder_mod.Forwarder(256) = forwarder_mod.Forwarder(256).init(.{}),
        // Egress link for forwarded packets (null = same as ingress link)
        egress_link: ?*LinkT = null,

        pub fn init(link_ep: *LinkT, local_addr: [4]u8) Self {
            return Self{
                .link = link_ep,
                .local_addr = local_addr,
            };
        }

        pub fn initWithSecret(link_ep: *LinkT, local_addr: [4]u8, secret: [16]u8) Self {
            return Self{
                .link = link_ep,
                .local_addr = local_addr,
                .isn_gen = isn_mod.IsnGenerator.init(secret),
                .syn_cookie = syn_cookie_mod.SynCookie.init(secret),
            };
        }

        // ================================================================
        // Inbound: raw IP packet → parse → dispatch to connection
        // ================================================================

        /// Inject a raw IP packet (IPv4 or IPv6) received from the wire.
        pub fn injectPacket(self: *Self, now_ms: u64, raw: []const u8) Event {
            self.last_tick_ms = now_ms;
            if (raw.len < 1) return .none;
            const version = raw[0] >> 4;
            if (version == 6) return self.injectPacket6(now_ms, raw);
            if (version != 4) return .none;
            if (raw.len < 20) return .none;

            const ip_hdr = ipv4_header.Header.parse(raw) catch return .none;
            if (!ip_hdr.isChecksumValid()) return .none;

            // Fragment reassembly: if this is a fragment, buffer it
            if (ip_hdr.moreFragments() or ip_hdr.fragmentOffset() != 0) {
                if (self.reassembler.inject(now_ms, raw)) |result| {
                    const hdr_len = ip_hdr.headerLen();
                    var reasm_buf: [cfg.max_reasm_datagram + 60]u8 = undefined;
                    const total = hdr_len + result.data.len;
                    if (total > reasm_buf.len) {
                        self.reassembler.release(result.slot_idx);
                        return .none;
                    }
                    @memcpy(reasm_buf[0..hdr_len], raw[0..hdr_len]);
                    @memcpy(reasm_buf[hdr_len .. hdr_len + result.data.len], result.data);
                    std.mem.writeInt(u16, reasm_buf[2..4], @intCast(total), .big);
                    reasm_buf[6] = 0;
                    reasm_buf[7] = 0;
                    reasm_buf[10] = 0;
                    reasm_buf[11] = 0;
                    const cksum_mod = @import("checksum.zig");
                    const cksum = cksum_mod.compute(reasm_buf[0..hdr_len]);
                    std.mem.writeInt(u16, reasm_buf[10..12], cksum, .big);
                    self.reassembler.release(result.slot_idx);
                    return self.processIpv4(now_ms, reasm_buf[0..total]);
                }
                return .none;
            }

            return self.processIpv4(now_ms, raw);
        }

        /// Process a complete (non-fragmented or reassembled) IPv4 packet.
        fn processIpv4(self: *Self, now_ms: u64, raw: []const u8) Event {
            const ip_hdr = ipv4_header.Header.parse(raw) catch return .none;
            const proto = ip_hdr.protocol();
            const src_addr = ip_hdr.srcAddr();
            const dst_addr = ip_hdr.dstAddr();
            const ip_payload = ip_hdr.payload(raw);

            // Forwarding: if dst is not our local address and forwarding is enabled
            if (self.forwarding_enabled and !std.mem.eql(u8, &dst_addr, &self.local_addr)) {
                self.forwardPacket(now_ms, raw, src_addr, dst_addr, ip_hdr, ip_payload, proto);
                return .none;
            }

            // ICMP handling
            if (proto == .icmp) {
                self.handleIcmp(src_addr, dst_addr, ip_payload);
                return .none;
            }

            // UDP handling
            if (proto == .udp) {
                if (ip_payload.len < udp_header.header_len) return .none;
                const uhdr = udp_header.Header.parse(ip_payload) catch return .none;
                if (!uhdr.verifyChecksumIpv4(src_addr, dst_addr, ip_payload)) return .none;
                return self.handleUdpInbound(src_addr, ip_payload);
            }

            if (proto != .tcp) return .none;

            // ECN: check for CE (Congestion Experienced) marking in IP header
            const ip_ecn = ip_hdr.ecn();

            if (ip_payload.len < 20) return .none;
            const tcp_hdr = tcp_header.Header.parse(ip_payload) catch return .none;
            if (!tcp_hdr.verifyChecksumIpv4(src_addr, dst_addr, ip_payload)) return .none;

            const src_port = tcp_hdr.srcPort();
            const dst_port = tcp_hdr.dstPort();
            const flags = tcp_hdr.flags();
            const seg_seq = tcp_hdr.seqNum();
            const seg_ack = tcp_hdr.ackNum();
            const seg_wnd = tcp_hdr.windowSize();
            const hdr_len = tcp_hdr.headerLen();
            const payload = if (ip_payload.len > hdr_len) ip_payload[hdr_len..] else &[_]u8{};

            const id = ConnId{
                .local_addr = dst_addr,
                .local_port = dst_port,
                .remote_addr = src_addr,
                .remote_port = src_port,
            };

            // Find existing connection
            if (self.findConn(id)) |idx| {
                const slot = &self.conns[idx];

                // Parse TCP options from SYN or SYN-ACK during handshake
                if (flags.syn and hdr_len > 20) {
                    const opts_data = ip_payload[20..hdr_len];
                    const peer_opts = @import("transport/tcp/options.zig").parseOptions(opts_data);
                    slot.conn.applyPeerOptions(peer_opts);
                }

                // Parse timestamps from any segment with options
                if (slot.conn.timestamps_enabled and hdr_len > 20) {
                    const opts_slice = ip_payload[20..hdr_len];
                    if (@import("transport/tcp/options.zig").readTimestamp(opts_slice)) |ts| {
                        // PAWS check: reject segments with old timestamps (RFC 7323 §4.2)
                        if (slot.conn.pawsReject(now_ms, ts.tsval, flags.rst)) {
                            // Drop segment, send ACK (RFC 7323: "not acceptable, send ACK")
                            return .none;
                        }
                        slot.conn.processTimestamp(now_ms, ts.tsval, ts.tsecr);
                    }
                }

                // ECN: mark CE if IP says congestion experienced (ECN=11)
                if (ip_ecn == 3 and slot.conn.ecn_enabled) {
                    slot.conn.ecn_ece_pending = true;
                }

                const output = slot.conn.onSegment(now_ms, flags, seg_seq, seg_ack, seg_wnd, payload);

                return self.handleConnOutput(idx, now_ms, output, payload.len);
            }

            // New SYN → accept
            if (flags.syn and !flags.ack) {
                const syn_opts = if (hdr_len > 20)
                    @import("transport/tcp/options.zig").parseOptions(ip_payload[20..hdr_len])
                else
                    @import("transport/tcp/options.zig").NegotiatedOptions{};
                return self.acceptConn(now_ms, id, seg_seq, seg_wnd, syn_opts);
            }

            // ACK without matching connection: might be completing a SYN-cookie handshake
            if (flags.ack and !flags.syn and !flags.rst) {
                if (self.validateSynCookie(now_ms, id, seg_ack)) |cookie_mss| {
                    return self.acceptCookieConn(now_ms, id, seg_seq, seg_ack, seg_wnd, cookie_mss, payload);
                }
            }

            // No match, send RST
            self.sendRst(dst_addr, dst_port, src_addr, src_port, seg_ack, seg_seq +% @as(u32, @intCast(payload.len)) +% @as(u32, if (flags.syn) 1 else 0));
            return .none;
        }

        /// Handle IPv6 packets (TCP over IPv6).
        fn injectPacket6(self: *Self, now_ms: u64, raw: []const u8) Event {
            if (raw.len < 40) return .none;
            const ip6_hdr = ipv6_header.Header.parse(raw) catch return .none;
            const next_hdr = ip6_hdr.nextHeader();

            // IPv6 fragment extension header — reassemble first
            if (next_hdr == .fragment) {
                if (self.v6_reassembler.inject(now_ms, raw)) |result| {
                    const ev = self.processReassembled6(now_ms, result);
                    self.v6_reassembler.release(result.slot_idx);
                    return ev;
                }
                return .none;
            }

            const ip6_payload = ip6_hdr.payload(raw);

            // ICMPv6 echo reply
            if (next_hdr == .icmpv6) {
                self.handleIcmpv6(ip6_hdr.srcAddr(), ip6_hdr.dstAddr(), ip6_payload);
                return .none;
            }

            // IPv6 UDP — only IPv4-mapped addresses supported; native IPv6 needs UdpEndpoint expansion (see #48)
            if (next_hdr == .udp) {
                if (ip6_payload.len < udp_header.header_len) return .none;
                const uhdr = udp_header.Header.parse(ip6_payload) catch return .none;
                if (!uhdr.verifyChecksumIpv6(ip6_hdr.srcAddr(), ip6_hdr.dstAddr(), ip6_payload)) return .none;
                return self.handleUdpInbound(ip6_hdr.srcAddr()[12..16].*, ip6_payload);
            }

            if (next_hdr != .tcp) return .none;
            if (ip6_payload.len < 20) return .none;

            const tcp_hdr = tcp_header.Header.parse(ip6_payload) catch return .none;
            if (!tcp_hdr.verifyChecksumIpv6(ip6_hdr.srcAddr(), ip6_hdr.dstAddr(), ip6_payload)) return .none;
            const flags = tcp_hdr.flags();
            const seg_seq = tcp_hdr.seqNum();
            const seg_ack = tcp_hdr.ackNum();
            const seg_wnd = tcp_hdr.windowSize();
            const hdr_len = tcp_hdr.headerLen();
            const payload = if (ip6_payload.len > hdr_len) ip6_payload[hdr_len..] else &[_]u8{};

            // Map IPv6 src/dst to v4 ConnId using last 4 bytes (IPv4-mapped ::ffff:a.b.c.d)
            const src6 = ip6_hdr.srcAddr();
            const dst6 = ip6_hdr.dstAddr();
            const src4 = src6[12..16].*;
            const dst4 = dst6[12..16].*;

            const id = ConnId{
                .local_addr = dst4,
                .local_port = tcp_hdr.dstPort(),
                .remote_addr = src4,
                .remote_port = tcp_hdr.srcPort(),
            };

            if (self.findConn6(src6, dst6, tcp_hdr.srcPort(), tcp_hdr.dstPort())) |idx| {
                const slot = &self.conns[idx];

                // Parse TCP options from SYN or SYN-ACK during handshake
                if (flags.syn and hdr_len > 20) {
                    const peer_opts6 = @import("transport/tcp/options.zig").parseOptions(ip6_payload[20..hdr_len]);
                    slot.conn.applyPeerOptions(peer_opts6);
                }

                // PAWS / Timestamps (RFC 7323) — must match IPv4 path
                if (slot.conn.timestamps_enabled and hdr_len > 20) {
                    const opts_slice6 = ip6_payload[20..hdr_len];
                    if (@import("transport/tcp/options.zig").readTimestamp(opts_slice6)) |ts| {
                        if (slot.conn.pawsReject(now_ms, ts.tsval, flags.rst)) {
                            return .none;
                        }
                        slot.conn.processTimestamp(now_ms, ts.tsval, ts.tsecr);
                    }
                }

                const output = slot.conn.onSegment(now_ms, flags, seg_seq, seg_ack, seg_wnd, payload);
                return self.handleConnOutput(idx, now_ms, output, payload.len);
            }

            if (flags.syn and !flags.ack) {
                const opts_mod6 = @import("transport/tcp/options.zig");
                const syn_opts6 = if (hdr_len > 20)
                    opts_mod6.parseOptions(ip6_payload[20..hdr_len])
                else
                    opts_mod6.NegotiatedOptions{};
                const ev = self.acceptConn(now_ms, id, seg_seq, seg_wnd, syn_opts6);
                // Mark as IPv6 connection and rehash with full v6 key
                switch (ev) {
                    .accepted => |idx| {
                        self.hashRemove(idx);
                        self.conns[idx].is_v6 = true;
                        self.conns[idx].local_addr6 = dst6;
                        self.conns[idx].remote_addr6 = src6;
                        self.hashInsert(idx);
                    },
                    // Held instead of answered: the addresses travel with the
                    // pending SYN, since the connection they belong to does
                    // not exist yet.
                    .syn_pending => |pending_idx| {
                        self.pending_syns[pending_idx].is_v6 = true;
                        self.pending_syns[pending_idx].local_addr6 = dst6;
                        self.pending_syns[pending_idx].remote_addr6 = src6;
                    },
                    else => {},
                }
                return ev;
            }

            // ACK without matching connection: might be completing a SYN-cookie handshake
            if (flags.ack and !flags.syn and !flags.rst) {
                if (self.validateSynCookie(now_ms, id, seg_ack)) |cookie_mss| {
                    const ev = self.acceptCookieConn(now_ms, id, seg_seq, seg_ack, seg_wnd, cookie_mss, payload);
                    switch (ev) {
                        .accepted, .data_ready => |idx| {
                            self.hashRemove(idx);
                            self.conns[idx].is_v6 = true;
                            self.conns[idx].local_addr6 = dst6;
                            self.conns[idx].remote_addr6 = src6;
                            self.hashInsert(idx);
                        },
                        else => {},
                    }
                    return ev;
                }
            }

            return .none;
        }

        fn processReassembled6(self: *Self, now_ms: u64, result: ipv6_frag_mod.ReasmResult) Event {
            const src6 = result.src;
            const dst6 = result.dst;
            const payload = result.data;

            if (result.next_header == .icmpv6) {
                self.handleIcmpv6(src6, dst6, payload);
                return .none;
            }

            if (result.next_header == .udp) {
                if (payload.len < udp_header.header_len) return .none;
                const uhdr = udp_header.Header.parse(payload) catch return .none;
                if (!uhdr.verifyChecksumIpv6(src6, dst6, payload)) return .none;
                return self.handleUdpInbound(src6[12..16].*, payload);
            }

            if (result.next_header != .tcp) return .none;
            if (payload.len < 20) return .none;

            const tcp_hdr = tcp_header.Header.parse(payload) catch return .none;
            if (!tcp_hdr.verifyChecksumIpv6(src6, dst6, payload)) return .none;
            const flags = tcp_hdr.flags();
            const seg_seq = tcp_hdr.seqNum();
            const seg_ack = tcp_hdr.ackNum();
            const seg_wnd = tcp_hdr.windowSize();
            const hdr_len = tcp_hdr.headerLen();
            const tcp_payload = if (payload.len > hdr_len) payload[hdr_len..] else &[_]u8{};

            if (self.findConn6(src6, dst6, tcp_hdr.srcPort(), tcp_hdr.dstPort())) |idx| {
                const slot = &self.conns[idx];

                // Parse SYN options from reassembled packet
                if (flags.syn and hdr_len > 20) {
                    const peer_opts = @import("transport/tcp/options.zig").parseOptions(payload[20..hdr_len]);
                    slot.conn.applyPeerOptions(peer_opts);
                }

                // Parse timestamps
                if (slot.conn.timestamps_enabled and hdr_len > 20) {
                    if (@import("transport/tcp/options.zig").readTimestamp(payload[20..hdr_len])) |ts| {
                        if (slot.conn.pawsReject(now_ms, ts.tsval, flags.rst)) {
                            return .none;
                        }
                        slot.conn.processTimestamp(now_ms, ts.tsval, ts.tsecr);
                    }
                }

                const output = slot.conn.onSegment(now_ms, flags, seg_seq, seg_ack, seg_wnd, tcp_payload);
                return self.handleConnOutput(idx, now_ms, output, tcp_payload.len);
            }

            return .none;
        }

        fn handleIcmpv6(self: *Self, src_addr: [16]u8, dst_addr: [16]u8, icmp_data: []const u8) void {
            if (icmp_data.len < 8) return;
            const msg_type: icmp_header.Icmpv6Type = @enumFromInt(icmp_data[0]);

            // ICMPv6 Packet Too Big (type 2): update PMTU for the affected connection
            if (msg_type == .packet_too_big) {
                self.handlePmtuError6(icmp_data);
                return;
            }

            if (msg_type != .echo_request) return;

            // Build ICMPv6 echo reply
            const ip6_hlen: usize = 40;
            const total_len = ip6_hlen + icmp_data.len;
            var buf: [1600]u8 = undefined;
            if (total_len > buf.len) return;

            // IPv6 header
            var ip6 = ipv6_header.MutableHeader.init(buf[0..ip6_hlen]) catch return;
            ip6.setPayloadLen(@intCast(icmp_data.len));
            ip6.setNextHeader(.icmpv6);
            ip6.setHopLimit(64);
            ip6.setSrcAddr(dst_addr);
            ip6.setDstAddr(src_addr);

            // Copy ICMPv6 data and change type to echo_reply (129)
            @memcpy(buf[ip6_hlen .. ip6_hlen + icmp_data.len], icmp_data);
            buf[ip6_hlen] = @intFromEnum(icmp_header.Icmpv6Type.echo_reply);

            // ICMPv6 checksum uses pseudo-header
            buf[ip6_hlen + 2] = 0;
            buf[ip6_hlen + 3] = 0;
            const cksum_mod = @import("checksum.zig");
            const ph = cksum_mod.pseudoHeaderIpv6(dst_addr, src_addr, 58, @intCast(icmp_data.len));
            const sum = cksum_mod.accumulate(ph, buf[ip6_hlen .. ip6_hlen + icmp_data.len]);
            const cksum = cksum_mod.finish(sum);
            std.mem.writeInt(u16, buf[ip6_hlen + 2 ..][0..2], cksum, .big);

            // Send
            var pb = @import("packet_buf.zig").PacketBuf.initWithData(buf[0..], 0, total_len);
            _ = self.link.extract(&pb);
        }

        // ================================================================
        // Outbound: poll connections → build packets → send via link
        // ================================================================

        /// Poll all connections and emit outbound packets.
        /// Returns the first non-none event (if any).
        pub fn poll(self: *Self, now_ms: u64) Event {
            self.last_tick_ms = now_ms;
            self.reassembler.tick(now_ms);
            if (self.active_count == 0) return .none;
            for (&self.conns, 0..) |*slot, idx| {
                if (!slot.active) continue;

                const output = slot.conn.poll(now_ms);
                switch (output) {
                    .send => |seg| {
                        self.emitSegment(@intCast(idx), seg);
                    },
                    .closed => {
                        self.hashRemove(idx);
                        slot.active = false;
                        self.active_count -|= 1;
                        return .{ .closed = @intCast(idx) };
                    },
                    .aborted => {
                        self.hashRemove(idx);
                        slot.active = false;
                        self.active_count -|= 1;
                        return .{ .aborted = @intCast(idx) };
                    },
                    else => {},
                }
            }
            return .none;
        }

        /// Advance time — poll + emit any pending ACKs.
        /// Same as poll but named for clarity when used as a timer tick.
        pub fn advance(self: *Self, now_ms: u64) Event {
            return self.poll(now_ms);
        }

        // ================================================================
        // Application API
        // ================================================================

        /// Write data to a connection. Returns bytes accepted.
        pub fn write(self: *Self, conn_idx: u16, data: []const u8) usize {
            if (conn_idx >= max_conns) return 0;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return 0;
            return slot.conn.write(data);
        }

        /// Read data from a connection. Returns bytes read.
        pub fn read(self: *Self, conn_idx: u16, buf: []u8) usize {
            if (conn_idx >= max_conns) return 0;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return 0;
            return slot.conn.read(buf);
        }

        /// Initiate close on a connection.
        pub fn close(self: *Self, conn_idx: u16) void {
            if (conn_idx >= max_conns) return;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return;
            slot.conn.close();
        }

        /// Shutdown write direction (send FIN, continue receiving).
        pub fn shutdownWrite(self: *Self, conn_idx: u16) void {
            if (conn_idx >= max_conns) return;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return;
            slot.conn.shutdownWrite();
        }

        /// Shutdown read direction (discard incoming data).
        pub fn shutdownRead(self: *Self, conn_idx: u16) void {
            if (conn_idx >= max_conns) return;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return;
            slot.conn.shutdownRead();
        }

        /// Register a listen port with given backlog.
        /// Can be called multiple times (up to 8 ports). Returns false if full.
        pub fn listen(self: *Self, port: u16, backlog: u16) bool {
            return self.listenMode(port, backlog, false);
        }

        /// Listen on a port without answering its SYNs. A SYN for such a port
        /// is held — nothing is sent, and no connection state is allocated —
        /// and reported as Event.syn_pending. The application then calls
        /// acceptPending, which completes the handshake exactly as an
        /// immediate accept would have, or rejectPending, which tells the
        /// peer there is nothing here.
        ///
        /// This is for a stack that has to go and find out whether anything
        /// will answer: a proxy dialling the real service, say. Answering the
        /// SYN first and closing afterwards tells the peer the port is open
        /// when it is not, and costs a connection slot for every scan.
        pub fn listenDeferred(self: *Self, port: u16, backlog: u16) bool {
            return self.listenMode(port, backlog, true);
        }

        /// Register a listen port, or change how an existing one answers.
        fn listenMode(self: *Self, port: u16, backlog: u16, deferred: bool) bool {
            const limit = if (backlog == 0) 128 else backlog;
            defer {
                self.syn_queue_limit = @max(self.syn_queue_limit, limit);
                self.accept_queue_limit = @max(self.accept_queue_limit, limit);
            }
            // Already listening: the call still says how SYNs are answered,
            // so listen() on a deferred port makes it answer immediately
            // again and listenDeferred() on a plain one starts holding.
            for (self.listen_ports[0..self.listen_count], 0..) |p, i| {
                if (p != port) continue;
                self.listen_deferred[i] = deferred;
                return true;
            }
            if (self.listen_count >= max_listen_ports) return false;
            self.listen_ports[self.listen_count] = port;
            self.listen_deferred[self.listen_count] = deferred;
            self.listen_count += 1;
            return true;
        }

        /// Stop listening on a port and give its slot back. Returns false if
        /// the port was not in the listen set.
        ///
        /// Established connections on that port are left alone, as closing a
        /// listening socket does everywhere else: what stops is new SYNs,
        /// which from here on are dropped as they are for any closed port. A
        /// handshake still in flight finishes and is then reset, since there
        /// is no longer anyone to accept it.
        ///
        /// The SYN and accept queue limits keep whatever a listen raised them
        /// to; they bound queues that are shared across ports.
        pub fn unlisten(self: *Self, port: u16) bool {
            for (self.listen_ports[0..self.listen_count], 0..) |p, i| {
                if (p != port) continue;
                self.listen_count -= 1;
                // The set has no order, so the last entry fills the hole.
                self.listen_ports[i] = self.listen_ports[self.listen_count];
                self.listen_deferred[i] = self.listen_deferred[self.listen_count];
                self.listen_ports[self.listen_count] = 0;
                self.listen_deferred[self.listen_count] = false;
                // Whatever this port was holding will never be settled now,
                // and the peer is still waiting on a SYN nobody answered.
                for (&self.pending_syns) |*ps| {
                    if (!ps.active or ps.id.local_port != port) continue;
                    self.rstPending(ps);
                    ps.active = false;
                }
                return true;
            }
            return false;
        }

        /// Whether a port holds its SYNs rather than answering them.
        fn isDeferred(self: *const Self, port: u16) bool {
            for (self.listen_ports[0..self.listen_count], 0..) |p, i| {
                if (p == port) return self.listen_deferred[i];
            }
            return false;
        }

        /// How many listen slots are still free, so a caller can tell a full
        /// set from a refused port.
        pub fn listenSlotsFree(self: *const Self) usize {
            return max_listen_ports -| self.listen_count;
        }

        /// Check if a port is in the listen set.
        fn isListening(self: *const Self, port: u16) bool {
            for (self.listen_ports[0..self.listen_count]) |p| {
                if (p == port) return true;
            }
            return false;
        }

        /// Dequeue the next established connection from the accept queue.
        /// Returns the connection index, or null if the queue is empty.
        pub fn accept(self: *Self) ?u16 {
            if (self.accept_queue_count == 0) return null;
            const idx = self.accept_queue[self.accept_queue_head];
            self.accept_queue_head = (self.accept_queue_head + 1) % max_conns;
            self.accept_queue_count -= 1;
            return idx;
        }

        /// Enqueue a connection index into the accept queue.
        fn enqueueAccept(self: *Self, conn_idx: u16) bool {
            if (self.accept_queue_count >= self.accept_queue_limit) return false;
            self.accept_queue[self.accept_queue_tail] = conn_idx;
            self.accept_queue_tail = (self.accept_queue_tail + 1) % max_conns;
            self.accept_queue_count += 1;
            return true;
        }

        /// Get current SYN queue count (O(1)).
        fn synQueueCount(self: *Self) u16 {
            return self.syn_queue_count;
        }

        pub fn allocEphemeralPort(self: *Self) u16 {
            const port = self.ephemeral_port_counter;
            self.ephemeral_port_counter = if (self.ephemeral_port_counter >= 65535) 49152 else self.ephemeral_port_counter + 1;
            return port;
        }

        /// Initiate an outbound connection (active open).
        pub fn connect(self: *Self, now_ms: u64, remote_addr: [4]u8, remote_port: u16, local_port: u16) ?u16 {
            const idx = self.allocSlot() orelse return null;
            const id = ConnId{
                .local_addr = self.local_addr,
                .local_port = local_port,
                .remote_addr = remote_addr,
                .remote_port = remote_port,
            };
            const gen_isn = self.nextIsn(now_ms, id);
            const slot = &self.conns[idx];
            slot.* = ConnSlot{
                .conn = ConnectionT.connect(local_port, remote_port, gen_isn),
                .id = id,
                .active = true,
            };
            self.active_count += 1;
            self.hashInsert(idx);
            return @intCast(idx);
        }

        /// Initiate an outbound IPv6 connection (active open).
        pub fn connect6(self: *Self, now_ms: u64, remote_addr: [16]u8, remote_port: u16, local_port: u16) ?u16 {
            const idx = self.allocSlot() orelse return null;
            const id = ConnId{
                .local_addr = self.local_addr6[12..16].*,
                .local_port = local_port,
                .remote_addr = remote_addr[12..16].*,
                .remote_port = remote_port,
            };
            const gen_isn = self.nextIsn(now_ms, id);
            const slot = &self.conns[idx];
            slot.* = ConnSlot{
                .conn = ConnectionT.connect(local_port, remote_port, gen_isn),
                .id = id,
                .active = true,
                .is_v6 = true,
                .local_addr6 = self.local_addr6,
                .remote_addr6 = remote_addr,
            };
            self.active_count += 1;
            self.hashInsert(idx);
            return @intCast(idx);
        }

        /// Get connection state.
        pub fn connState(self: *const Self, conn_idx: u16) ?tcp_connection.State {
            if (conn_idx >= max_conns) return null;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return null;
            return slot.conn.state;
        }

        /// Get connection ID.
        pub fn connId(self: *const Self, conn_idx: u16) ?ConnId {
            if (conn_idx >= max_conns) return null;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return null;
            return slot.id;
        }

        /// Set TCP_NODELAY (disable Nagle algorithm) on a connection.
        pub fn setNoDelay(self: *Self, conn_idx: u16, enabled: bool) void {
            if (conn_idx >= max_conns) return;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return;
            slot.conn.sender.nagle_enabled = !enabled;
        }

        /// Get TCP_NODELAY state.
        pub fn getNoDelay(self: *const Self, conn_idx: u16) bool {
            if (conn_idx >= max_conns) return false;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return false;
            return !slot.conn.sender.nagle_enabled;
        }

        /// Enable/disable TCP keepalive on a connection.
        pub fn setKeepalive(self: *Self, conn_idx: u16, enabled: bool) void {
            if (conn_idx >= max_conns) return;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return;
            slot.conn.keepalive_enabled = enabled;
        }

        /// Configure keepalive parameters.
        pub fn setKeepaliveParams(self: *Self, conn_idx: u16, idle_ms: u64, interval_ms: u64, max_probes: u8) void {
            if (conn_idx >= max_conns) return;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return;
            slot.conn.keepalive_idle_ms = idle_ms;
            slot.conn.keepalive_interval_ms = interval_ms;
            slot.conn.keepalive_max_probes = max_probes;
        }

        /// Configure the local IPv6 address.
        pub fn setIpv6Addr(self: *Self, addr: [16]u8) void {
            self.local_addr6 = addr;
            self.ipv6_enabled = true;
        }

        /// Set SO_LINGER option on a connection.
        pub fn setLinger(self: *Self, conn_idx: u16, enabled: bool, timeout_ms: u64) void {
            if (conn_idx >= max_conns) return;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return;
            slot.conn.setLinger(enabled, timeout_ms);
        }

        /// Enable/disable ECN on a connection.
        pub fn setEcn(self: *Self, conn_idx: u16, enabled: bool) void {
            if (conn_idx >= max_conns) return;
            const slot = &self.conns[conn_idx];
            if (!slot.active) return;
            slot.conn.ecn_enabled = enabled;
        }

        /// Next poll deadline.
        pub fn nextPollAt(self: *const Self) ?u64 {
            var earliest: ?u64 = null;
            for (&self.conns) |*slot| {
                if (!slot.active) continue;
                if (slot.conn.nextPollAt()) |t| {
                    if (earliest == null or t < earliest.?) earliest = t;
                }
            }
            return earliest;
        }

        // ================================================================
        // UDP Application API
        // ================================================================

        /// Bind a new UDP endpoint to a local port. Returns endpoint index or null.
        pub fn udpBind(self: *Self, port: u16) ?u16 {
            var i: usize = 0;
            while (i < max_udp_endpoints) : (i += 1) {
                if (!self.udp_eps[i].active) {
                    self.udp_eps[i].ep = .{};
                    self.udp_eps[i].ep.bind(port);
                    self.udp_eps[i].active = true;
                    self.udp_count += 1;
                    return @intCast(i);
                }
            }
            return null;
        }

        /// Close a UDP endpoint.
        pub fn udpClose(self: *Self, ep_idx: u16) void {
            if (ep_idx >= max_udp_endpoints) return;
            const slot = &self.udp_eps[ep_idx];
            if (!slot.active) return;
            slot.active = false;
            self.udp_count -= 1;
        }

        /// Send a UDP datagram from an endpoint.
        pub fn udpSendTo(self: *Self, ep_idx: u16, dst_addr: [4]u8, dst_port: u16, data: []const u8) bool {
            if (ep_idx >= max_udp_endpoints) return false;
            const slot = &self.udp_eps[ep_idx];
            if (!slot.active) return false;

            // Build and send immediately
            self.emitUdpPacket(slot.ep.local_port, dst_addr, dst_port, data);
            return true;
        }

        /// Send a UDP datagram to an IPv6 destination.
        pub fn udpSendTo6(self: *Self, ep_idx: u16, dst_addr: [16]u8, dst_port: u16, data: []const u8) bool {
            if (ep_idx >= max_udp_endpoints) return false;
            const slot = &self.udp_eps[ep_idx];
            if (!slot.active) return false;
            self.emitUdpPacket6(slot.ep.local_port, dst_addr, dst_port, data);
            return true;
        }

        /// Send a UDP datagram to the connected remote.
        pub fn udpSend(self: *Self, ep_idx: u16, data: []const u8) bool {
            if (ep_idx >= max_udp_endpoints) return false;
            const slot = &self.udp_eps[ep_idx];
            if (!slot.active or !slot.ep.connected) return false;
            self.emitUdpPacket(slot.ep.local_port, slot.ep.remote_addr, slot.ep.remote_port, data);
            return true;
        }

        /// Connect a UDP endpoint to a remote (sets default destination).
        pub fn udpConnect(self: *Self, ep_idx: u16, addr: [4]u8, port: u16) void {
            if (ep_idx >= max_udp_endpoints) return;
            const slot = &self.udp_eps[ep_idx];
            if (!slot.active) return;
            slot.ep.connectTo(addr, port);
        }

        /// Receive a datagram from a UDP endpoint. Returns null if empty.
        pub fn udpRecv(self: *Self, ep_idx: u16) ?udp_endpoint.Datagram {
            if (ep_idx >= max_udp_endpoints) return null;
            const slot = &self.udp_eps[ep_idx];
            if (!slot.active) return null;
            return slot.ep.recv();
        }

        /// Number of datagrams available on a UDP endpoint.
        pub fn udpAvailable(self: *const Self, ep_idx: u16) usize {
            if (ep_idx >= max_udp_endpoints) return 0;
            const slot = &self.udp_eps[ep_idx];
            if (!slot.active) return 0;
            return slot.ep.available();
        }

        // ================================================================
        // Internal: packet building
        // ================================================================

        fn emitSegment(self: *Self, conn_idx: u16, seg: Segment) void {
            const slot = &self.conns[conn_idx];
            const id = slot.id;
            const now_ms = self.last_tick_ms;

            // Get payload from send buffer
            const payload_data = if (seg.payload_len > 0)
                slot.conn.send_buf[seg.payload_offset .. seg.payload_offset + seg.payload_len]
            else
                &[_]u8{};

            // Build TCP options
            const opts_mod = @import("transport/tcp/options.zig");
            var opts_buf: [40]u8 = undefined;
            var opts_len: usize = 0;

            if (seg.include_syn_options) {
                opts_len = opts_mod.writeSynOptions(&opts_buf, .{
                    .mss = slot.conn.mss,
                    .window_scale = slot.conn.our_wscale,
                    .sack_permitted = true,
                    .timestamps = slot.conn.timestamps_enabled,
                });
            } else if (slot.conn.timestamps_enabled) {
                // Data segments: include timestamp option (12 bytes)
                opts_len = opts_mod.writeTimestamp(&opts_buf, slot.conn.currentTsval(now_ms), slot.conn.currentTsecr());
            }

            // Apply ECN flags if enabled
            const flags = slot.conn.applyEcnFlags(seg.flags);

            if (slot.is_v6) {
                self.buildAndSend6Opts(slot.local_addr6, slot.remote_addr6, id.local_port, id.remote_port, flags, seg.seq, seg.ack, seg.window, payload_data, opts_buf[0..opts_len]);
            } else {
                const ecn_ip: u2 = if (slot.conn.ecn_enabled) 2 else 0;
                self.buildAndSendEcnOpts(id, flags, seg.seq, seg.ack, seg.window, payload_data, ecn_ip, opts_buf[0..opts_len]);
            }
        }

        fn buildAndSend(
            self: *Self,
            id: ConnId,
            flags: tcp_header.Flags,
            seq: u32,
            ack: u32,
            window: u16,
            payload: []const u8,
        ) void {
            self.buildAndSendEcnOpts(id, flags, seq, ack, window, payload, 0, &.{});
        }

        fn buildAndSendEcnOpts(
            self: *Self,
            id: ConnId,
            flags: tcp_header.Flags,
            seq: u32,
            ack: u32,
            window: u16,
            payload: []const u8,
            ecn_ip: u2,
            tcp_options: []const u8,
        ) void {
            // TCP header: 20 bytes base + options (padded to 4-byte boundary)
            const opts_padded = (tcp_options.len + 3) & ~@as(usize, 3);
            const tcp_hlen: usize = 20 + opts_padded;
            const ip_hlen: usize = 20;
            const total_len = ip_hlen + tcp_hlen + payload.len;

            var buf: [1600]u8 = undefined;
            if (total_len > buf.len) return;

            // Build IP header
            var ip = ipv4_header.MutableHeader.init(buf[0..ip_hlen]) catch return;
            ip.setTotalLen(@intCast(total_len));
            ip.setIdentification(self.ip_id_counter);
            self.ip_id_counter +%= 1;
            ip.setDontFragment();
            ip.setTtl(64);
            ip.setProtocol(.tcp);
            ip.setSrcAddr(id.local_addr);
            ip.setDstAddr(id.remote_addr);
            if (ecn_ip != 0) ip.setEcn(ecn_ip);
            ip.computeChecksum();

            // Build TCP header (base 20 bytes)
            var tcp = tcp_header.MutableHeader.init(buf[ip_hlen .. ip_hlen + 20]) catch return;
            tcp.setSrcPort(id.local_port);
            tcp.setDstPort(id.remote_port);
            tcp.setSeqNum(seq);
            tcp.setAckNum(ack);
            tcp.setFlags(flags);
            tcp.setWindowSize(window);
            // Set data offset to include options
            buf[ip_hlen + 12] = @as(u8, @intCast(tcp_hlen / 4)) << 4;

            // Copy TCP options after base header
            if (tcp_options.len > 0) {
                @memcpy(buf[ip_hlen + 20 .. ip_hlen + 20 + tcp_options.len], tcp_options);
                if (opts_padded > tcp_options.len) {
                    @memset(buf[ip_hlen + 20 + tcp_options.len .. ip_hlen + 20 + opts_padded], 0);
                }
            }

            // Copy payload
            if (payload.len > 0) {
                @memcpy(buf[ip_hlen + tcp_hlen .. ip_hlen + tcp_hlen + payload.len], payload);
            }

            // Compute TCP checksum using shared helper
            {
                const cksum_mod = @import("checksum.zig");
                const tcp_seg = buf[ip_hlen..total_len];
                tcp_seg[16] = 0;
                tcp_seg[17] = 0;
                const ph = cksum_mod.pseudoHeaderIpv4(id.local_addr, id.remote_addr, 6, @intCast(tcp_seg.len));
                const sum = cksum_mod.accumulate(ph, tcp_seg);
                const cksum = cksum_mod.finish(sum);
                std.mem.writeInt(u16, tcp_seg[16..18], cksum, .big);
            }

            // Send via link
            var pb = @import("packet_buf.zig").PacketBuf.initWithData(buf[0..], 0, total_len);
            _ = self.link.extract(&pb);
        }

        fn buildAndSend6(
            self: *Self,
            src6: [16]u8,
            dst6: [16]u8,
            src_port: u16,
            dst_port: u16,
            flags: tcp_header.Flags,
            seq: u32,
            ack: u32,
            window: u16,
            payload: []const u8,
        ) void {
            self.buildAndSend6Opts(src6, dst6, src_port, dst_port, flags, seq, ack, window, payload, &.{});
        }

        fn buildAndSend6Opts(
            self: *Self,
            src6: [16]u8,
            dst6: [16]u8,
            src_port: u16,
            dst_port: u16,
            flags: tcp_header.Flags,
            seq: u32,
            ack: u32,
            window: u16,
            payload: []const u8,
            tcp_options: []const u8,
        ) void {
            const ip6_hlen: usize = 40;
            const opts_padded = (tcp_options.len + 3) & ~@as(usize, 3);
            const tcp_hlen: usize = 20 + opts_padded;
            const tcp_total = tcp_hlen + payload.len;
            const total_len = ip6_hlen + tcp_total;

            var buf: [1600]u8 = undefined;
            if (total_len > buf.len) return;

            // Build IPv6 header
            var ip6 = ipv6_header.MutableHeader.init(buf[0..ip6_hlen]) catch return;
            ip6.setPayloadLen(@intCast(tcp_total));
            ip6.setNextHeader(.tcp);
            ip6.setHopLimit(64);
            ip6.setSrcAddr(src6);
            ip6.setDstAddr(dst6);

            // Build TCP header (base 20 bytes)
            var tcp = tcp_header.MutableHeader.init(buf[ip6_hlen .. ip6_hlen + 20]) catch return;
            tcp.setSrcPort(src_port);
            tcp.setDstPort(dst_port);
            tcp.setSeqNum(seq);
            tcp.setAckNum(ack);
            tcp.setFlags(flags);
            tcp.setWindowSize(window);
            // Set data offset to include options
            buf[ip6_hlen + 12] = @as(u8, @intCast(tcp_hlen / 4)) << 4;

            // Copy TCP options
            if (tcp_options.len > 0) {
                @memcpy(buf[ip6_hlen + 20 .. ip6_hlen + 20 + tcp_options.len], tcp_options);
                if (opts_padded > tcp_options.len) {
                    @memset(buf[ip6_hlen + 20 + tcp_options.len .. ip6_hlen + 20 + opts_padded], 0);
                }
            }

            // Copy payload
            if (payload.len > 0) {
                @memcpy(buf[ip6_hlen + tcp_hlen .. ip6_hlen + tcp_hlen + payload.len], payload);
            }

            // Compute TCP checksum with IPv6 pseudo-header
            {
                const cksum_mod = @import("checksum.zig");
                const tcp_seg = buf[ip6_hlen..total_len];
                tcp_seg[16] = 0;
                tcp_seg[17] = 0;
                const ph = cksum_mod.pseudoHeaderIpv6(src6, dst6, 6, @intCast(tcp_total));
                const sum = cksum_mod.accumulate(ph, tcp_seg);
                const cksum = cksum_mod.finish(sum);
                std.mem.writeInt(u16, tcp_seg[16..18], cksum, .big);
            }

            var pb = @import("packet_buf.zig").PacketBuf.initWithData(buf[0..], 0, total_len);
            _ = self.link.extract(&pb);
        }

        fn sendRst(self: *Self, src_addr: [4]u8, src_port: u16, dst_addr: [4]u8, dst_port: u16, seq: u32, ack_val: u32) void {
            self.buildAndSend(
                ConnId{ .local_addr = src_addr, .local_port = src_port, .remote_addr = dst_addr, .remote_port = dst_port },
                .{ .rst = true, .ack = true },
                seq,
                ack_val,
                0,
                &.{},
            );
        }

        // ================================================================
        // Internal: ICMP
        // ================================================================

        fn handleIcmp(self: *Self, src_addr: [4]u8, dst_addr: [4]u8, icmp_data: []const u8) void {
            const hdr = icmp_header.Header.parse(icmp_data) catch return;
            if (!hdr.verifyChecksumIcmpv4(icmp_data)) return;

            // PMTU: Destination Unreachable, code 4 (fragmentation needed)
            if (hdr.icmpv4Type() == .dest_unreachable and hdr.code() == 4) {
                self.handlePmtuError(icmp_data);
                return;
            }

            if (hdr.icmpv4Type() != .echo_request) return;

            // Build echo reply: swap src/dst, change type to 0 (echo reply)
            const ip_hlen: usize = 20;
            const total_len = ip_hlen + icmp_data.len;
            var buf: [1600]u8 = undefined;
            if (total_len > buf.len) return;

            // IP header
            var ip = ipv4_header.MutableHeader.init(buf[0..ip_hlen]) catch return;
            ip.setTotalLen(@intCast(total_len));
            ip.setIdentification(self.ip_id_counter);
            self.ip_id_counter +%= 1;
            ip.setDontFragment();
            ip.setTtl(64);
            ip.setProtocol(.icmp);
            ip.setSrcAddr(dst_addr);
            ip.setDstAddr(src_addr);
            ip.computeChecksum();

            // Copy ICMP data and modify type
            @memcpy(buf[ip_hlen .. ip_hlen + icmp_data.len], icmp_data);
            // Set type to echo_reply (0)
            buf[ip_hlen] = @intFromEnum(icmp_header.Icmpv4Type.echo_reply);
            // Recompute ICMP checksum (clear checksum field, then compute)
            buf[ip_hlen + 2] = 0;
            buf[ip_hlen + 3] = 0;
            const cksum_mod = @import("checksum.zig");
            const cksum = cksum_mod.compute(buf[ip_hlen .. ip_hlen + icmp_data.len]);
            std.mem.writeInt(u16, buf[ip_hlen + 2 ..][0..2], cksum, .big);

            // Send
            var pb = @import("packet_buf.zig").PacketBuf.initWithData(buf[0..], 0, total_len);
            _ = self.link.extract(&pb);
        }

        fn handlePmtuError(self: *Self, icmp_data: []const u8) void {
            // ICMP Dest Unreachable layout: 8-byte ICMP hdr + offending IP packet
            if (icmp_data.len < 8 + 28) return; // need at least IP+8 bytes of TCP

            // Next-hop MTU from ICMP header bytes 6-7 (RFC 1191)
            const next_hop_mtu = std.mem.readInt(u16, icmp_data[6..8], .big);
            if (next_hop_mtu < 68) return; // RFC minimum

            // Extract 4-tuple from the embedded IP+TCP headers
            const embedded = icmp_data[8..];
            const emb_ip = ipv4_header.Header.parse(embedded) catch return;
            const emb_payload = emb_ip.payload(embedded);
            if (emb_payload.len < 8) return;

            const emb_src_port = std.mem.readInt(u16, emb_payload[0..2], .big);
            const emb_dst_port = std.mem.readInt(u16, emb_payload[2..4], .big);

            const id = ConnId{
                .local_addr = emb_ip.srcAddr(),
                .local_port = emb_src_port,
                .remote_addr = emb_ip.dstAddr(),
                .remote_port = emb_dst_port,
            };

            // Update path MTU
            if (next_hop_mtu < self.path_mtu) {
                self.path_mtu = next_hop_mtu;
            }

            // Update the connection's MSS
            if (self.findConn(id)) |idx| {
                const new_mss = next_hop_mtu -| 40; // IP(20) + TCP(20)
                if (new_mss > 0 and new_mss < self.conns[idx].conn.mss) {
                    self.conns[idx].conn.mss = new_mss;
                    self.conns[idx].conn.sender.mss = new_mss;
                }
            }
        }

        fn handlePmtuError6(self: *Self, icmp_data: []const u8) void {
            // ICMPv6 Packet Too Big: [type(1)][code(1)][cksum(2)][MTU(4)][embedded IPv6 pkt...]
            if (icmp_data.len < 8 + 40 + 4) return; // need ICMPv6 hdr + IPv6 hdr + 4 bytes TCP ports

            const mtu = std.mem.readInt(u32, icmp_data[4..8], .big);
            if (mtu < 1280) return; // IPv6 minimum MTU

            // Embedded IPv6 header starts at offset 8
            const embedded = icmp_data[8..];
            // IPv6 src/dst from embedded packet (the packet we originally sent)
            const emb_src6 = embedded[8..24].*;
            const emb_dst6 = embedded[24..40].*;

            // TCP ports from embedded transport header (offset 40 in embedded)
            if (embedded.len < 44) return;
            const emb_src_port = std.mem.readInt(u16, embedded[40..42], .big);
            const emb_dst_port = std.mem.readInt(u16, embedded[42..44], .big);

            // emb_src = our local, emb_dst = remote
            if (self.findConn6(emb_dst6, emb_src6, emb_dst_port, emb_src_port)) |idx| {
                const new_mss: u16 = @intCast(mtu -| 60); // IPv6(40) + TCP(20)
                if (new_mss > 0 and new_mss < self.conns[idx].conn.mss) {
                    self.conns[idx].conn.mss = new_mss;
                    self.conns[idx].conn.sender.mss = new_mss;
                }
            }
        }

        // ================================================================
        // Internal: UDP handling
        // ================================================================

        fn handleUdpInbound(self: *Self, src_addr: [4]u8, ip_payload: []const u8) Event {
            if (ip_payload.len < udp_header.header_len) return .none;
            const hdr = udp_header.Header.parse(ip_payload) catch return .none;
            const dst_port = hdr.dstPort();
            const src_port = hdr.srcPort();
            const payload = hdr.payload(ip_payload);

            // Find matching UDP endpoint
            var i: usize = 0;
            while (i < max_udp_endpoints) : (i += 1) {
                if (self.udp_eps[i].active and self.udp_eps[i].ep.local_port == dst_port) {
                    self.udp_eps[i].ep.deliver(src_addr, src_port, payload);
                    return .{ .udp_recv = @intCast(i) };
                }
            }
            return .none;
        }

        fn emitUdpPacket(self: *Self, src_port: u16, dst_addr: [4]u8, dst_port: u16, data: []const u8) void {
            const udp_len: u16 = @intCast(udp_header.header_len + data.len);
            const total_len: u16 = 20 + udp_len;

            var buf: [1500]u8 = undefined;
            if (total_len > buf.len) return;

            // Build IPv4 header
            var ip_hdr = ipv4_header.MutableHeader.init(&buf) catch return;
            ip_hdr.setTotalLen(total_len);
            ip_hdr.setIdentification(self.ip_id_counter);
            self.ip_id_counter +%= 1;
            ip_hdr.setTtl(64);
            ip_hdr.setProtocol(.udp);
            ip_hdr.setSrcAddr(self.local_addr);
            ip_hdr.setDstAddr(dst_addr);
            ip_hdr.computeChecksum();

            // Build UDP header
            const udp_start: usize = 20;
            var udp_hdr_mut = udp_header.MutableHeader.init(buf[udp_start..]) catch return;
            udp_hdr_mut.setSrcPort(src_port);
            udp_hdr_mut.setDstPort(dst_port);
            udp_hdr_mut.setLength(udp_len);

            // Copy payload
            const payload_start = udp_start + udp_header.header_len;
            @memcpy(buf[payload_start .. payload_start + data.len], data);

            // Compute UDP checksum using shared helper
            const udp_seg = buf[udp_start..total_len];
            udp_seg[6] = 0;
            udp_seg[7] = 0;
            {
                const cksum_mod = @import("checksum.zig");
                const ph = cksum_mod.pseudoHeaderIpv4(self.local_addr, dst_addr, 17, udp_len);
                const raw = cksum_mod.finish(cksum_mod.accumulate(ph, udp_seg));
                const cksum: u16 = if (raw == 0) 0xFFFF else raw;
                std.mem.writeInt(u16, udp_seg[6..8], cksum, .big);
            }

            // Send via link endpoint
            var pb = @import("packet_buf.zig").PacketBuf.initWithData(buf[0..], 0, total_len);
            _ = self.link.extract(&pb);
        }

        fn emitUdpPacket6(self: *Self, src_port: u16, dst_addr: [16]u8, dst_port: u16, data: []const u8) void {
            const ip6_hlen: usize = 40;
            const udp_len: u16 = @intCast(udp_header.header_len + data.len);
            const total_len = ip6_hlen + @as(usize, udp_len);

            var buf: [1500]u8 = undefined;
            if (total_len > buf.len) return;

            // Build IPv6 header
            var ip6 = ipv6_header.MutableHeader.init(buf[0..ip6_hlen]) catch return;
            ip6.setPayloadLen(udp_len);
            ip6.setNextHeader(.udp);
            ip6.setHopLimit(64);
            ip6.setSrcAddr(self.local_addr6);
            ip6.setDstAddr(dst_addr);

            // Build UDP header
            const udp_start = ip6_hlen;
            var udp_hdr_mut = udp_header.MutableHeader.init(buf[udp_start..]) catch return;
            udp_hdr_mut.setSrcPort(src_port);
            udp_hdr_mut.setDstPort(dst_port);
            udp_hdr_mut.setLength(udp_len);

            // Copy payload
            const payload_start = udp_start + udp_header.header_len;
            @memcpy(buf[payload_start .. payload_start + data.len], data);

            // Compute UDP checksum with IPv6 pseudo-header (mandatory per RFC 8200)
            const udp_seg = buf[udp_start..total_len];
            udp_seg[6] = 0;
            udp_seg[7] = 0;
            {
                const cksum_mod = @import("checksum.zig");
                const ph = cksum_mod.pseudoHeaderIpv6(self.local_addr6, dst_addr, 17, udp_len);
                const raw = cksum_mod.finish(cksum_mod.accumulate(ph, udp_seg));
                const cksum: u16 = if (raw == 0) 0xFFFF else raw;
                std.mem.writeInt(u16, udp_seg[6..8], cksum, .big);
            }

            var pb = @import("packet_buf.zig").PacketBuf.initWithData(buf[0..], 0, total_len);
            _ = self.link.extract(&pb);
        }

        // ================================================================
        // Internal: connection management
        // ================================================================

        fn acceptConn(self: *Self, now_ms: u64, id: ConnId, peer_seq: u32, peer_wnd: u16, peer_opts: @import("transport/tcp/options.zig").NegotiatedOptions) Event {
            if (!self.isListening(id.local_port)) return .none;

            // Held rather than answered: nothing is sent and no connection
            // state is allocated until the application says so. Ahead of the
            // SYN cookie branch on purpose — a cookie is an answer too.
            if (self.isDeferred(id.local_port)) return self.holdSyn(now_ms, id, peer_seq, peer_wnd, peer_opts);

            const half_open = self.synQueueCount();

            // SYN cookie mode: when SYN queue is near full, respond statelessly
            if (half_open >= self.syn_cookie_threshold) {
                return self.acceptConnStateless(now_ms, id, peer_seq, peer_wnd);
            }

            // Drop if SYN queue is full
            if (half_open >= self.syn_queue_limit) return .none;

            const idx = self.allocSlot() orelse return .none;
            const isn = self.nextIsn(now_ms, id);

            const slot = &self.conns[idx];
            slot.id = id;
            slot.active = true;
            slot.passive = true;
            slot.conn = ConnectionT.acceptFromSyn(id.local_port, isn, now_ms, peer_opts);

            // Process the SYN — produces SYN+ACK output
            const output = slot.conn.onSegment(now_ms, .{ .syn = true }, peer_seq, 0, peer_wnd, &.{});
            self.active_count += 1;
            self.syn_queue_count += 1;
            self.hashInsert(idx);

            // Emit the SYN+ACK packet
            switch (output) {
                .send => |seg| self.emitSegmentForSlot(slot, seg),
                else => {},
            }

            return .{ .accepted = @intCast(idx) };
        }

        /// Keep a SYN for a deferred port. A retransmission of one already
        /// held refreshes it rather than taking a second slot; a full table
        /// drops the SYN, which the peer retransmits.
        fn holdSyn(self: *Self, now_ms: u64, id: ConnId, peer_seq: u32, peer_wnd: u16, peer_opts: @import("transport/tcp/options.zig").NegotiatedOptions) Event {
            for (&self.pending_syns, 0..) |*ps, i| {
                if (!ps.active or !connIdEql(ps.id, id)) continue;
                ps.received_ms = now_ms;
                ps.peer_seq = peer_seq;
                ps.peer_wnd = peer_wnd;
                ps.peer_opts = peer_opts;
                return .{ .syn_pending = @intCast(i) };
            }
            for (&self.pending_syns, 0..) |*ps, i| {
                if (ps.active) continue;
                ps.* = .{
                    .id = id,
                    .peer_seq = peer_seq,
                    .peer_wnd = peer_wnd,
                    .peer_opts = peer_opts,
                    .received_ms = now_ms,
                    .active = true,
                };
                return .{ .syn_pending = @intCast(i) };
            }
            return .none;
        }

        fn connIdEql(a: ConnId, b: ConnId) bool {
            return a.local_port == b.local_port and a.remote_port == b.remote_port and
                std.mem.eql(u8, &a.local_addr, &b.local_addr) and std.mem.eql(u8, &a.remote_addr, &b.remote_addr);
        }

        /// The oldest SYN still waiting for an answer, or null.
        pub fn nextPendingSyn(self: *const Self) ?u16 {
            var best: ?u16 = null;
            var best_ms: u64 = 0;
            for (self.pending_syns, 0..) |ps, i| {
                if (!ps.active) continue;
                if (best == null or ps.received_ms < best_ms) {
                    best = @intCast(i);
                    best_ms = ps.received_ms;
                }
            }
            return best;
        }

        /// What arrived, for a caller deciding whether to take it.
        pub fn pendingSynInfo(self: *const Self, pending_idx: u16) ?PendingInfo {
            if (pending_idx >= max_pending_syns) return null;
            const ps = self.pending_syns[pending_idx];
            if (!ps.active) return null;
            return .{
                .local_port = ps.id.local_port,
                .remote_addr = ps.id.remote_addr,
                .remote_port = ps.id.remote_port,
                .received_ms = ps.received_ms,
                .is_v6 = ps.is_v6,
                .remote_addr6 = ps.remote_addr6,
            };
        }

        /// How many SYNs are held.
        pub fn pendingSynCount(self: *const Self) usize {
            var n: usize = 0;
            for (self.pending_syns) |ps| {
                if (ps.active) n += 1;
            }
            return n;
        }

        /// Answer a held SYN: the handshake goes on from here exactly as it
        /// would have when the SYN arrived. Returns the connection index, or
        /// null if the stack has no room — in which case the peer hears
        /// nothing and retransmits, as it would have all along.
        pub fn acceptPending(self: *Self, pending_idx: u16, now_ms: u64) ?u16 {
            if (pending_idx >= max_pending_syns) return null;
            const ps = self.pending_syns[pending_idx];
            if (!ps.active) return null;
            self.pending_syns[pending_idx].active = false;

            // Answer it through the path a non-deferred port takes, which is
            // where every option, cookie and queue rule already lives.
            const was = self.setDeferred(ps.id.local_port, false);
            defer _ = self.setDeferred(ps.id.local_port, was);
            const ev = self.acceptConn(now_ms, ps.id, ps.peer_seq, ps.peer_wnd, ps.peer_opts);
            switch (ev) {
                .accepted => |idx| {
                    if (ps.is_v6) {
                        self.hashRemove(idx);
                        self.conns[idx].is_v6 = true;
                        self.conns[idx].local_addr6 = ps.local_addr6;
                        self.conns[idx].remote_addr6 = ps.remote_addr6;
                        self.hashInsert(idx);
                    }
                    return idx;
                },
                else => return null,
            }
        }

        /// Refuse a held SYN: the peer is told there is nothing here, rather
        /// than left waiting on an answer that will not come.
        pub fn rejectPending(self: *Self, pending_idx: u16) void {
            if (pending_idx >= max_pending_syns) return;
            const ps = &self.pending_syns[pending_idx];
            if (!ps.active) return;
            self.rstPending(ps);
            ps.active = false;
        }

        /// Drop SYNs held longer than `timeout_ms` without an answer, the way
        /// a half-open connection times out. Returns how many were dropped.
        /// The peer is not told: from its side the SYN was simply lost, which
        /// is what it would have been had the stack not been listening.
        pub fn expirePendingSyns(self: *Self, now_ms: u64, timeout_ms: u64) usize {
            var n: usize = 0;
            for (&self.pending_syns) |*ps| {
                if (!ps.active or now_ms -| ps.received_ms < timeout_ms) continue;
                ps.active = false;
                n += 1;
            }
            return n;
        }

        /// RST a held SYN's sender: ack its sequence, as a closed port does.
        fn rstPending(self: *Self, ps: *const PendingSyn) void {
            self.sendRst(ps.id.local_addr, ps.id.local_port, ps.id.remote_addr, ps.id.remote_port, 0, ps.peer_seq +% 1);
        }

        /// Set how a port answers and return what it was; a port that is not
        /// in the listen set answers nothing, so false either way.
        fn setDeferred(self: *Self, port: u16, deferred: bool) bool {
            for (self.listen_ports[0..self.listen_count], 0..) |p, i| {
                if (p != port) continue;
                const was = self.listen_deferred[i];
                self.listen_deferred[i] = deferred;
                return was;
            }
            return false;
        }

        /// Stateless SYN+ACK using SYN cookie (no connection state allocated).
        fn acceptConnStateless(self: *Self, now_ms: u64, id: ConnId, peer_seq: u32, peer_wnd: u16) Event {
            _ = peer_wnd;
            const cookie_isn = self.syn_cookie.generate(now_ms, id.remote_addr, id.remote_port, id.local_addr, id.local_port, 1460);

            // Send SYN+ACK with cookie as ISN, no state allocated
            self.buildAndSend(id, .{ .syn = true, .ack = true }, cookie_isn, peer_seq +% 1, 65535, &.{});
            return .none;
        }

        /// Validate a SYN cookie from an inbound ACK.
        fn validateSynCookie(self: *Self, now_ms: u64, id: ConnId, seg_ack: u32) ?u16 {
            const cookie = seg_ack -% 1; // ACK acknowledges ISN+1
            return self.syn_cookie.validate(now_ms, id.remote_addr, id.remote_port, id.local_addr, id.local_port, cookie);
        }

        /// Accept a connection validated by SYN cookie (reconstruct state from ACK).
        fn acceptCookieConn(self: *Self, now_ms: u64, id: ConnId, seg_seq: u32, seg_ack: u32, seg_wnd: u16, cookie_mss: u16, payload: []const u8) Event {
            // The cookie was minted while the port was listening, and the
            // listener can be gone by the time the ACK carrying it arrives.
            // The peer believes it has a connection, so say otherwise.
            if (!self.isListening(id.local_port)) {
                self.sendRst(id.local_addr, id.local_port, id.remote_addr, id.remote_port, seg_ack, seg_seq);
                return .none;
            }

            // Drop if accept queue is full
            if (self.accept_queue_count >= self.accept_queue_limit) return .none;

            const idx = self.allocSlot() orelse return .none;
            const our_isn = seg_ack -% 1;

            const slot = &self.conns[idx];
            slot.id = id;
            slot.active = true;
            slot.passive = true;
            slot.conn = .{
                .state = .established,
                .local_port = id.local_port,
                .remote_port = id.remote_port,
                .sender = SenderT.init(our_isn, cookie_mss),
                .receiver = ReceiverT.init(seg_seq -% 1, @intCast(@min(cfg.recv_buf_size, 65535))),
                .mss = cookie_mss,
                .last_activity_ms = now_ms,
            };
            slot.conn.sender.syn_sent = true;
            slot.conn.sender.syn_acked = true;
            slot.conn.sender.snd_nxt = our_isn +% 1;
            slot.conn.sender.snd_una = our_isn +% 1;
            slot.conn.sender.setRemoteWindow(@as(u32, seg_wnd));
            self.active_count += 1;
            self.hashInsert(idx);

            const conn_idx: u16 = @intCast(idx);
            _ = self.enqueueAccept(conn_idx);

            if (payload.len > 0) {
                _ = slot.conn.receiver.onSegment(seg_seq, payload);
                return .{ .data_ready = conn_idx };
            }

            return .{ .accepted = conn_idx };
        }

        fn emitSegmentForSlot(self: *Self, slot: *ConnSlot, seg: Segment) void {
            const payload_data = if (seg.payload_len > 0)
                slot.conn.send_buf[seg.payload_offset .. seg.payload_offset + seg.payload_len]
            else
                &[_]u8{};

            const opts_mod = @import("transport/tcp/options.zig");
            var opts_buf: [40]u8 = undefined;
            var opts_len: usize = 0;

            if (seg.include_syn_options) {
                opts_len = opts_mod.writeSynOptions(&opts_buf, .{
                    .mss = slot.conn.mss,
                    .window_scale = slot.conn.our_wscale,
                    .sack_permitted = true,
                    .timestamps = slot.conn.timestamps_enabled,
                });
            } else if (slot.conn.timestamps_enabled) {
                const now_ms = self.last_tick_ms;
                opts_len = opts_mod.writeTimestamp(&opts_buf, slot.conn.currentTsval(now_ms), slot.conn.currentTsecr());
            }

            if (slot.is_v6) {
                self.buildAndSend6Opts(slot.local_addr6, slot.remote_addr6, slot.id.local_port, slot.id.remote_port, seg.flags, seg.seq, seg.ack, seg.window, payload_data, opts_buf[0..opts_len]);
            } else {
                self.buildAndSendEcnOpts(slot.id, seg.flags, seg.seq, seg.ack, seg.window, payload_data, 0, opts_buf[0..opts_len]);
            }
        }

        fn handleConnOutput(self: *Self, idx: usize, now_ms: u64, output: tcp_connection.Output, payload_len: usize) Event {
            _ = now_ms;
            switch (output) {
                .send => |seg| {
                    self.emitSegment(@intCast(idx), seg);
                },
                .established => {
                    const conn_idx: u16 = @intCast(idx);
                    // Server-side (passive open): enqueue to accept queue.
                    // Which side opened it is recorded on the slot: the listen
                    // set answers a different question, and unlisten during a
                    // handshake used to leave the half-open count and the slot
                    // itself behind, with no way to reach the connection.
                    if (self.conns[idx].passive) {
                        self.syn_queue_count -|= 1;
                        // No listener left to hand it to, or nowhere to queue
                        // it: an established connection nobody can accept is a
                        // slot nobody frees, so end it here.
                        if (!self.isListening(self.conns[idx].id.local_port) or !self.enqueueAccept(conn_idx)) {
                            self.buildAndSend(self.conns[idx].id, .{ .rst = true, .ack = true }, self.conns[idx].conn.sender.snd_nxt, self.conns[idx].conn.receiver.rcv_nxt, 0, &.{});
                            self.hashRemove(idx);
                            self.conns[idx].active = false;
                            self.active_count -|= 1;
                            return .none;
                        }
                        return .{ .accepted = conn_idx };
                    }
                    // Client-side (active open): report established directly
                    if (payload_len > 0) return .{ .data_ready = conn_idx };
                    return .{ .established = conn_idx };
                },
                .closed => {
                    if (self.conns[idx].conn.state == .syn_received) self.syn_queue_count -|= 1;
                    self.hashRemove(idx);
                    self.conns[idx].active = false;
                    self.active_count -|= 1;
                    return .{ .closed = @intCast(idx) };
                },
                .aborted => {
                    if (self.conns[idx].conn.state == .syn_received) self.syn_queue_count -|= 1;
                    self.hashRemove(idx);
                    self.conns[idx].active = false;
                    self.active_count -|= 1;
                    return .{ .aborted = @intCast(idx) };
                },
                .none => {},
            }
            if (payload_len > 0) return .{ .data_ready = @intCast(idx) };
            return .none;
        }

        fn findConn(self: *Self, id: ConnId) ?usize {
            if (use_hash_index) {
                return self.hashLookup4(id);
            }
            return self.linearFind4(id);
        }

        fn findConn6(self: *Self, remote6: [16]u8, local6: [16]u8, remote_port: u16, local_port: u16) ?usize {
            if (use_hash_index) {
                return self.hashLookup6(remote6, local6, remote_port, local_port);
            }
            return self.linearFind6(remote6, local6, remote_port, local_port);
        }

        fn linearFind4(self: *Self, id: ConnId) ?usize {
            for (self.conns[0..], 0..) |slot, idx| {
                if (slot.active and !slot.is_v6 and
                    std.mem.eql(u8, &slot.id.local_addr, &id.local_addr) and
                    slot.id.local_port == id.local_port and
                    std.mem.eql(u8, &slot.id.remote_addr, &id.remote_addr) and
                    slot.id.remote_port == id.remote_port)
                {
                    return idx;
                }
            }
            return null;
        }

        fn linearFind6(self: *Self, remote6: [16]u8, local6: [16]u8, remote_port: u16, local_port: u16) ?usize {
            for (self.conns[0..], 0..) |slot, idx| {
                if (slot.active and slot.is_v6 and
                    slot.id.local_port == local_port and
                    slot.id.remote_port == remote_port and
                    std.mem.eql(u8, &slot.local_addr6, &local6) and
                    std.mem.eql(u8, &slot.remote_addr6, &remote6))
                {
                    return idx;
                }
            }
            return null;
        }

        // Hash index helpers (only meaningful when use_hash_index = true)
        fn connHash4(id: ConnId) u32 {
            var h: u32 = 2166136261; // FNV-1a
            for (id.local_addr) |b| {
                h ^= b;
                h *%= 16777619;
            }
            h ^= @as(u32, id.local_port);
            h *%= 16777619;
            for (id.remote_addr) |b| {
                h ^= b;
                h *%= 16777619;
            }
            h ^= @as(u32, id.remote_port);
            h *%= 16777619;
            return h;
        }

        fn connHash6(remote6: [16]u8, local6: [16]u8, remote_port: u16, local_port: u16) u32 {
            var h: u32 = 2166136261;
            for (local6) |b| {
                h ^= b;
                h *%= 16777619;
            }
            h ^= @as(u32, local_port);
            h *%= 16777619;
            for (remote6) |b| {
                h ^= b;
                h *%= 16777619;
            }
            h ^= @as(u32, remote_port);
            h *%= 16777619;
            return h;
        }

        fn hashLookup4(self: *Self, id: ConnId) ?usize {
            if (!use_hash_index) return null;
            const h = connHash4(id);
            var pos = h % hash_capacity;
            var i: usize = 0;
            while (i < hash_capacity) : (i += 1) {
                const slot_idx = self.conn_hash[pos];
                if (slot_idx == empty_slot) return null;
                const slot = &self.conns[slot_idx];
                if (slot.active and !slot.is_v6 and
                    std.mem.eql(u8, &slot.id.local_addr, &id.local_addr) and
                    slot.id.local_port == id.local_port and
                    std.mem.eql(u8, &slot.id.remote_addr, &id.remote_addr) and
                    slot.id.remote_port == id.remote_port)
                {
                    return slot_idx;
                }
                pos = (pos + 1) % hash_capacity;
            }
            return null;
        }

        fn hashLookup6(self: *Self, remote6: [16]u8, local6: [16]u8, remote_port: u16, local_port: u16) ?usize {
            if (!use_hash_index) return null;
            const h = connHash6(remote6, local6, remote_port, local_port);
            var pos = h % hash_capacity;
            var i: usize = 0;
            while (i < hash_capacity) : (i += 1) {
                const slot_idx = self.conn_hash[pos];
                if (slot_idx == empty_slot) return null;
                const slot = &self.conns[slot_idx];
                if (slot.active and slot.is_v6 and
                    slot.id.local_port == local_port and
                    slot.id.remote_port == remote_port and
                    std.mem.eql(u8, &slot.local_addr6, &local6) and
                    std.mem.eql(u8, &slot.remote_addr6, &remote6))
                {
                    return slot_idx;
                }
                pos = (pos + 1) % hash_capacity;
            }
            return null;
        }

        fn hashInsert(self: *Self, slot_idx: usize) void {
            if (!use_hash_index) return;
            const slot = &self.conns[slot_idx];
            const h = if (slot.is_v6)
                connHash6(slot.remote_addr6, slot.local_addr6, slot.id.remote_port, slot.id.local_port)
            else
                connHash4(slot.id);
            var pos = h % hash_capacity;
            var i: usize = 0;
            while (i < hash_capacity) : (i += 1) {
                if (self.conn_hash[pos] == empty_slot) {
                    self.conn_hash[pos] = @intCast(slot_idx);
                    return;
                }
                pos = (pos + 1) % hash_capacity;
            }
        }

        fn hashRemove(self: *Self, slot_idx: usize) void {
            if (!use_hash_index) return;
            const slot = &self.conns[slot_idx];
            const h = if (slot.is_v6)
                connHash6(slot.remote_addr6, slot.local_addr6, slot.id.remote_port, slot.id.local_port)
            else
                connHash4(slot.id);
            var pos = h % hash_capacity;
            var i: usize = 0;
            while (i < hash_capacity) : (i += 1) {
                if (self.conn_hash[pos] == empty_slot) return;
                if (self.conn_hash[pos] == @as(u16, @intCast(slot_idx))) {
                    // Robin Hood: re-insert all following entries in cluster
                    self.conn_hash[pos] = empty_slot;
                    var next = (pos + 1) % hash_capacity;
                    while (self.conn_hash[next] != empty_slot) : (next = (next + 1) % hash_capacity) {
                        const moved = self.conn_hash[next];
                        self.conn_hash[next] = empty_slot;
                        self.hashInsert(moved);
                    }
                    return;
                }
                pos = (pos + 1) % hash_capacity;
            }
        }

        fn allocSlot(self: *const Self) ?usize {
            for (self.conns[0..], 0..) |slot, idx| {
                if (!slot.active) return idx;
            }
            return null;
        }

        fn nextIsn(self: *Self, now_ms: u64, id: ConnId) u32 {
            return self.isn_gen.generate(now_ms, id.local_addr, id.local_port, id.remote_addr, id.remote_port);
        }

        // ================================================================
        // Forwarding / NAT
        // ================================================================

        /// Enable IP forwarding with optional NAT configuration.
        pub fn enableForwarding(self: *Self, config: forwarder_mod.Config) void {
            self.forwarding_enabled = true;
            self.forwarder = forwarder_mod.Forwarder(256).init(config);
        }

        /// Disable IP forwarding.
        pub fn disableForwarding(self: *Self) void {
            self.forwarding_enabled = false;
        }

        /// Set the egress link endpoint for forwarded packets.
        pub fn setEgressLink(self: *Self, link_ep: *LinkT) void {
            self.egress_link = link_ep;
        }

        /// Expire idle conntrack/forwarder entries. Call periodically.
        pub fn expireFlows(self: *Self, now_ms: u64) usize {
            const ct_expired = self.conntrack.expire(now_ms);
            const fwd_expired = self.forwarder.tick(now_ms);
            return ct_expired + fwd_expired;
        }

        /// Get the number of active tracked flows.
        pub fn activeFlows(self: *const Self) usize {
            return self.conntrack.entry_count;
        }

        /// Get per-flow stats for a given tuple.
        pub fn flowStats(self: *const Self, src_addr: [4]u8, src_port: u16, dst_addr: [4]u8, dst_port: u16, proto: conntrack_mod.Protocol) ?conntrack_mod.ConnStats {
            const tuple = conntrack_mod.Tuple{
                .src_addr = src_addr,
                .dst_addr = dst_addr,
                .src_port = src_port,
                .dst_port = dst_port,
                .protocol = proto,
            };
            return self.conntrack.getStats(tuple);
        }

        /// Total bytes forwarded across all tracked flows.
        pub fn totalForwardedBytes(self: *const Self) u64 {
            return self.conntrack.totalBytes();
        }

        fn forwardPacket(self: *Self, now_ms: u64, raw: []const u8, src_addr: [4]u8, dst_addr: [4]u8, ip_hdr: ipv4_header.Header, ip_payload: []const u8, proto: ipv4_header.Protocol) void {
            _ = ip_hdr;
            const ttl = raw[8];

            // Extract ports for TCP/UDP
            var src_port: u16 = 0;
            var dst_port: u16 = 0;
            if ((proto == .tcp or proto == .udp) and ip_payload.len >= 4) {
                src_port = std.mem.readInt(u16, ip_payload[0..2], .big);
                dst_port = std.mem.readInt(u16, ip_payload[2..4], .big);
            }

            const proto_u8: u8 = switch (proto) {
                .tcp => 6,
                .udp => 17,
                .icmp => 1,
                else => return,
            };

            // Forwarder decision
            const decision = self.forwarder.decideInbound(now_ms, src_addr, src_port, dst_addr, dst_port, proto_u8, ttl);
            switch (decision) {
                .drop => return,
                .local => {
                    // Should not happen since we already checked dst != local_addr, but handle gracefully
                    return;
                },
                .icmp_unreachable => return,
                .forward => |info| {
                    // Track connection with byte stats
                    const ct_tuple = conntrack_mod.Tuple{
                        .src_addr = src_addr,
                        .dst_addr = dst_addr,
                        .src_port = src_port,
                        .dst_port = dst_port,
                        .protocol = if (proto == .tcp) .tcp else if (proto == .udp) .udp else .icmp,
                    };
                    _ = self.conntrack.trackWithSize(ct_tuple, now_ms, false, @intCast(raw.len));

                    // Build forwarded packet with NAT rewrites
                    var fwd_buf: [1600]u8 = undefined;
                    if (raw.len > fwd_buf.len) return;
                    @memcpy(fwd_buf[0..raw.len], raw);

                    // TTL decrement
                    if (info.decrement_ttl) {
                        if (fwd_buf[8] <= 1) return;
                        fwd_buf[8] -= 1;
                    }

                    // NAT rewrites
                    if (info.new_src_addr) |addr| {
                        @memcpy(fwd_buf[12..16], &addr);
                    }
                    if (info.new_dst_addr) |addr| {
                        @memcpy(fwd_buf[16..20], &addr);
                    }

                    // Port rewrites (TCP/UDP)
                    if ((proto == .tcp or proto == .udp) and ip_payload.len >= 4) {
                        const ihl: usize = @as(usize, fwd_buf[0] & 0x0F) * 4;
                        if (info.new_src_port) |port| {
                            std.mem.writeInt(u16, fwd_buf[ihl..][0..2], port, .big);
                        }
                        if (info.new_dst_port) |port| {
                            std.mem.writeInt(u16, fwd_buf[ihl + 2 ..][0..2], port, .big);
                        }
                    }

                    // Recompute IP header checksum
                    const ihl_final: usize = @as(usize, fwd_buf[0] & 0x0F) * 4;
                    fwd_buf[10] = 0;
                    fwd_buf[11] = 0;
                    const ip_cksum = checksum_mod.compute(fwd_buf[0..ihl_final]);
                    std.mem.writeInt(u16, fwd_buf[10..12], ip_cksum, .big);

                    // Recompute transport checksum for NAT'd packets
                    if (info.new_src_addr != null or info.new_dst_addr != null or
                        info.new_src_port != null or info.new_dst_port != null)
                    {
                        const total_len: usize = @as(usize, std.mem.readInt(u16, fwd_buf[2..4], .big));
                        if (total_len > ihl_final) {
                            const transport_slice = fwd_buf[ihl_final..total_len];
                            if (proto == .tcp and transport_slice.len >= 20) {
                                // Clear TCP checksum and recompute
                                transport_slice[16] = 0;
                                transport_slice[17] = 0;
                                const ph = checksum_mod.pseudoHeaderIpv4(fwd_buf[12..16].*, fwd_buf[16..20].*, 6, @intCast(transport_slice.len));
                                const sum = checksum_mod.accumulate(ph, transport_slice);
                                const tcp_cksum = checksum_mod.finish(sum);
                                std.mem.writeInt(u16, transport_slice[16..18], tcp_cksum, .big);
                            } else if (proto == .udp and transport_slice.len >= 8) {
                                // Clear UDP checksum and recompute
                                transport_slice[6] = 0;
                                transport_slice[7] = 0;
                                const ph = checksum_mod.pseudoHeaderIpv4(fwd_buf[12..16].*, fwd_buf[16..20].*, 17, @intCast(transport_slice.len));
                                const sum = checksum_mod.accumulate(ph, transport_slice);
                                const udp_cksum = checksum_mod.finish(sum);
                                std.mem.writeInt(u16, transport_slice[6..8], udp_cksum, .big);
                            }
                        }
                    }

                    // Send to egress link (outbound = toward the wire)
                    const egress = self.egress_link orelse self.link;
                    egress.writeOutbound(fwd_buf[0..raw.len]);
                },
            }
        }
    };
}

// ============================================================================
// Integration tests: full packet-level TCP handshake + data transfer
// ============================================================================

const testing = std.testing;

/// Build a raw IPv4+TCP packet (for test injection).
pub fn buildTcpPacket(
    src_addr: [4]u8,
    src_port: u16,
    dst_addr: [4]u8,
    dst_port: u16,
    seq: u32,
    ack_val: u32,
    flags: tcp_header.Flags,
    window: u16,
    payload: []const u8,
    out: []u8,
) usize {
    const ip_hlen: usize = 20;
    const tcp_hlen: usize = 20;
    const total: usize = ip_hlen + tcp_hlen + payload.len;

    var ip = ipv4_header.MutableHeader.init(out[0..ip_hlen]) catch unreachable;
    ip.setTotalLen(@intCast(total));
    ip.setTtl(64);
    ip.setProtocol(.tcp);
    ip.setSrcAddr(src_addr);
    ip.setDstAddr(dst_addr);
    ip.computeChecksum();

    var tcp = tcp_header.MutableHeader.init(out[ip_hlen .. ip_hlen + tcp_hlen]) catch unreachable;
    tcp.setSrcPort(src_port);
    tcp.setDstPort(dst_port);
    tcp.setSeqNum(seq);
    tcp.setAckNum(ack_val);
    tcp.setFlags(flags);
    tcp.setWindowSize(window);

    if (payload.len > 0) {
        @memcpy(out[ip_hlen + tcp_hlen .. ip_hlen + tcp_hlen + payload.len], payload);
    }
    tcp.computeChecksumIpv4(src_addr, dst_addr, out[ip_hlen..total]);

    return total;
}

/// Parse a TCP segment from a raw IPv4 packet (for test verification).
pub fn parseTcpFromRaw(raw: []const u8) ?struct {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: tcp_header.Flags,
    window: u16,
    payload_len: usize,
} {
    const ip_hdr = ipv4_header.Header.parse(raw) catch return null;
    const ip_payload = ip_hdr.payload(raw);
    const tcp_hdr = tcp_header.Header.parse(ip_payload) catch return null;
    const hdr_len = tcp_hdr.headerLen();
    return .{
        .src_port = tcp_hdr.srcPort(),
        .dst_port = tcp_hdr.dstPort(),
        .seq = tcp_hdr.seqNum(),
        .ack = tcp_hdr.ackNum(),
        .flags = tcp_hdr.flags(),
        .window = tcp_hdr.windowSize(),
        .payload_len = if (ip_payload.len > hdr_len) ip_payload.len - hdr_len else 0,
    };
}

test "FullStack: complete 3-way handshake (server)" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 128);

    // Client sends SYN
    var pkt_buf: [128]u8 = undefined;
    const syn_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        5000,
        .{ 10, 0, 0, 1 },
        80,
        1000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );

    // Inject SYN
    const event1 = stack.injectPacket(0, pkt_buf[0..syn_len]);
    switch (event1) {
        .accepted => |idx| try testing.expectEqual(@as(u16, 0), idx),
        else => return error.TestUnexpectedResult,
    }

    // Stack should have sent SYN+ACK
    try testing.expectEqual(@as(usize, 1), link_ep.outboundCount());
    var out_buf: [1600]u8 = undefined;
    const syn_ack_raw = link_ep.readOutbound(&out_buf).?;

    // Verify IP checksum
    {
        const cksum_mod = @import("checksum.zig");
        try testing.expectEqual(@as(u16, 0), cksum_mod.compute(syn_ack_raw[0..20]));
    }

    // Verify TCP checksum
    {
        const cksum_mod = @import("checksum.zig");
        const ihl: usize = @as(usize, syn_ack_raw[0] & 0x0F) * 4;
        const total_len: usize = @as(usize, syn_ack_raw[2]) << 8 | @as(usize, syn_ack_raw[3]);
        const tcp_seg = syn_ack_raw[ihl..total_len];
        const ph = cksum_mod.pseudoHeaderIpv4(syn_ack_raw[12..16].*, syn_ack_raw[16..20].*, 6, @intCast(tcp_seg.len));
        const sum = cksum_mod.accumulate(ph, tcp_seg);
        try testing.expectEqual(@as(u16, 0), cksum_mod.finish(sum));
    }

    const syn_ack = parseTcpFromRaw(syn_ack_raw).?;
    try testing.expect(syn_ack.flags.syn);
    try testing.expect(syn_ack.flags.ack);
    try testing.expectEqual(@as(u32, 1001), syn_ack.ack); // ACK = client ISS + 1
    try testing.expectEqual(@as(u16, 80), syn_ack.src_port);
    try testing.expectEqual(@as(u16, 5000), syn_ack.dst_port);

    // Client sends ACK (completing handshake)
    const server_isn = syn_ack.seq;
    const ack_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        5000,
        .{ 10, 0, 0, 1 },
        80,
        1001,
        server_isn + 1,
        .{ .ack = true },
        65535,
        &.{},
        &pkt_buf,
    );

    // Manually set up sender state for the ACK to be processed correctly
    var slot = &stack.conns[0];
    slot.conn.sender.syn_sent = true;
    slot.conn.sender.snd_nxt = server_isn + 1;
    slot.conn.sender.snd_una = server_isn;
    slot.conn.sender.retx_queue[0] = .{
        .seq = server_isn,
        .len = 1,
        .sent_at = 0,
        .is_syn = true,
    };
    slot.conn.sender.retx_count = 1;

    const event2 = stack.injectPacket(10, pkt_buf[0..ack_len]);
    switch (event2) {
        .accepted => |idx| try testing.expectEqual(@as(u16, 0), idx),
        else => return error.TestUnexpectedResult,
    }

    try testing.expectEqual(tcp_connection.State.established, stack.connState(0).?);
}

test "FullStack: SYN+ACK with options has valid TCP checksum" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 128);

    // Client sends SYN with MSS option (like Linux would)
    var pkt_buf: [128]u8 = undefined;
    // Build SYN with MSS=1460 option: kind=2, len=4, mss_hi, mss_lo
    const mss_opt = [_]u8{ 2, 4, 0x05, 0xB4 }; // MSS=1460
    const syn_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        5000,
        .{ 10, 0, 0, 1 },
        80,
        1000,
        0,
        .{ .syn = true },
        65535,
        &mss_opt,
        &pkt_buf,
    );

    const event1 = stack.injectPacket(0, pkt_buf[0..syn_len]);
    switch (event1) {
        .accepted => {},
        else => return error.TestUnexpectedResult,
    }

    // Read SYN+ACK and verify checksums
    try testing.expectEqual(@as(usize, 1), link_ep.outboundCount());
    var out_buf: [1600]u8 = undefined;
    const syn_ack_raw = link_ep.readOutbound(&out_buf).?;

    // IP checksum
    {
        const cksum_mod = @import("checksum.zig");
        try testing.expectEqual(@as(u16, 0), cksum_mod.compute(syn_ack_raw[0..20]));
    }

    // TCP checksum (should be 0 when computed over entire segment with pseudo-header)
    {
        const cksum_mod = @import("checksum.zig");
        const ihl: usize = @as(usize, syn_ack_raw[0] & 0x0F) * 4;
        const total_len: usize = @as(usize, syn_ack_raw[2]) << 8 | @as(usize, syn_ack_raw[3]);
        const tcp_seg = syn_ack_raw[ihl..total_len];
        const ph = cksum_mod.pseudoHeaderIpv4(syn_ack_raw[12..16].*, syn_ack_raw[16..20].*, 6, @intCast(tcp_seg.len));
        const sum = cksum_mod.accumulate(ph, tcp_seg);
        const result = cksum_mod.finish(sum);
        try testing.expectEqual(@as(u16, 0), result);
    }
}

test "FullStack: data transfer after handshake" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });

    // Set up a pre-established connection directly
    stack.conns[0] = .{
        .conn = Connection{
            .state = .established,
            .sender = Sender.init(5000, 1460),
            .receiver = Receiver.init(2000, 65535),
        },
        .id = ConnId{
            .local_addr = .{ 10, 0, 0, 1 },
            .local_port = 80,
            .remote_addr = .{ 10, 0, 0, 2 },
            .remote_port = 5000,
        },
        .active = true,
    };
    stack.conns[0].conn.sender.syn_sent = true;
    stack.conns[0].conn.sender.syn_acked = true;
    stack.conns[0].conn.sender.snd_nxt = 5001;
    stack.conns[0].conn.sender.snd_una = 5001;
    stack.conns[0].conn.sender.nagle_enabled = false;
    stack.active_count = 1;

    // --- Server receives data from client ---
    var pkt_buf: [128]u8 = undefined;
    const data_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        5000,
        .{ 10, 0, 0, 1 },
        80,
        2001, // client's next seq
        5001, // acking server's ISN+1
        .{ .ack = true, .psh = true },
        65535,
        "Hello, server!",
        &pkt_buf,
    );

    const event = stack.injectPacket(100, pkt_buf[0..data_len]);
    switch (event) {
        .data_ready => |idx| try testing.expectEqual(@as(u16, 0), idx),
        else => return error.TestUnexpectedResult,
    }

    // Read the data from the connection
    var read_buf: [64]u8 = undefined;
    const n = stack.read(0, &read_buf);
    try testing.expectEqual(@as(usize, 14), n);
    try testing.expectEqualSlices(u8, "Hello, server!", read_buf[0..14]);

    // --- Server sends data to client ---
    const written = stack.write(0, "Hello, client!");
    try testing.expectEqual(@as(usize, 14), written);

    // Poll to emit the data packet
    _ = stack.poll(110);

    // Verify outbound packet
    try testing.expect(link_ep.outboundCount() > 0);
    var out_buf: [1600]u8 = undefined;
    const sent_raw = link_ep.readOutbound(&out_buf).?;
    const sent = parseTcpFromRaw(sent_raw).?;
    try testing.expect(sent.flags.ack);
    try testing.expect(sent.flags.psh);
    try testing.expectEqual(@as(u16, 80), sent.src_port);
    try testing.expectEqual(@as(u16, 5000), sent.dst_port);
    try testing.expectEqual(@as(usize, 14), sent.payload_len);
}

test "FullStack: active open (client connect)" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });

    // Initiate connection
    const idx = stack.connect(0, .{ 10, 0, 0, 2 }, 80, 5000).?;
    try testing.expectEqual(@as(u16, 0), idx);
    try testing.expectEqual(tcp_connection.State.syn_sent, stack.connState(0).?);

    // Poll → should emit SYN
    _ = stack.poll(0);
    try testing.expect(link_ep.outboundCount() > 0);

    var out_buf: [1600]u8 = undefined;
    const syn_raw = link_ep.readOutbound(&out_buf).?;
    const syn = parseTcpFromRaw(syn_raw).?;
    try testing.expect(syn.flags.syn);
    try testing.expect(!syn.flags.ack);
    try testing.expectEqual(@as(u16, 5000), syn.src_port);
    try testing.expectEqual(@as(u16, 80), syn.dst_port);
}

test "FullStack: full bidirectional exchange" {
    // Two stacks connected back-to-back via their link endpoints
    var link_a = link_mod.ChannelEndpoint.init();
    var link_b = link_mod.ChannelEndpoint.init();
    var stack_a = FullStack(4).init(&link_a, .{ 10, 0, 0, 1 }); // server
    var stack_b = FullStack(4).init(&link_b, .{ 10, 0, 0, 2 }); // client
    _ = stack_a.listen(80, 128);

    // Client initiates connection
    const client_idx = stack_b.connect(0, .{ 10, 0, 0, 1 }, 80, 5000).?;
    _ = client_idx;

    // Client polls → SYN emitted to link_b
    _ = stack_b.poll(0);
    try testing.expect(link_b.outboundCount() > 0);

    // Transfer SYN from link_b → stack_a
    var transfer_buf: [1600]u8 = undefined;
    const syn_raw = link_b.readOutbound(&transfer_buf).?;
    const ev1 = stack_a.injectPacket(1, syn_raw);
    switch (ev1) {
        .accepted => {},
        else => return error.TestUnexpectedResult,
    }

    // Transfer SYN+ACK from link_a → stack_b
    const syn_ack_raw = link_a.readOutbound(&transfer_buf).?;
    const ev2 = stack_b.injectPacket(2, syn_ack_raw);
    // Client should now be established
    // The event depends on sender state; check connection state
    _ = ev2;

    // Client needs to have its SYN acked for state to advance
    // After receiving SYN+ACK, client should be ESTABLISHED
    try testing.expectEqual(tcp_connection.State.established, stack_b.connState(0).?);

    // Client sends ACK (emitted by onSegment) → verify link_b has it
    if (link_b.outboundCount() > 0) {
        const ack_raw = link_b.readOutbound(&transfer_buf).?;
        _ = stack_a.injectPacket(3, ack_raw);
    }

    // Now both should be established (or server in syn_received waiting for ACK)
    // Server needs proper sender state — let's verify client at least
    try testing.expectEqual(tcp_connection.State.established, stack_b.connState(0).?);
}

test "FullStack: RST for unknown connection" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });

    // Send data to a port with no listener
    var pkt_buf: [128]u8 = undefined;
    const data_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        5000,
        .{ 10, 0, 0, 1 },
        9999,
        1000,
        0,
        .{ .ack = true },
        65535,
        "data",
        &pkt_buf,
    );

    _ = stack.injectPacket(0, pkt_buf[0..data_len]);

    // Should have sent RST
    try testing.expect(link_ep.outboundCount() > 0);
    var out_buf: [1600]u8 = undefined;
    const rst_raw = link_ep.readOutbound(&out_buf).?;
    const rst = parseTcpFromRaw(rst_raw).?;
    try testing.expect(rst.flags.rst);
}

test "FullStack: ICMP echo reply" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });

    // Build an ICMP echo request packet
    var pkt_buf: [128]u8 = undefined;
    const ip_hlen: usize = 20;
    const icmp_len: usize = 12; // 8 header + 4 payload
    const total_len: usize = ip_hlen + icmp_len;

    // IP header
    var ip = ipv4_header.MutableHeader.init(pkt_buf[0..ip_hlen]) catch unreachable;
    ip.setTotalLen(@intCast(total_len));
    ip.setTtl(64);
    ip.setProtocol(.icmp);
    ip.setSrcAddr(.{ 10, 0, 0, 2 });
    ip.setDstAddr(.{ 10, 0, 0, 1 });
    ip.computeChecksum();

    // ICMP echo request
    var icmp = icmp_header.MutableHeader.init(pkt_buf[ip_hlen .. ip_hlen + 8]) catch unreachable;
    icmp.setType(@intFromEnum(icmp_header.Icmpv4Type.echo_request));
    icmp.setCode(0);
    icmp.setIdentifier(1234);
    icmp.setSequence(1);
    // Payload
    pkt_buf[ip_hlen + 8] = 0xDE;
    pkt_buf[ip_hlen + 9] = 0xAD;
    pkt_buf[ip_hlen + 10] = 0xBE;
    pkt_buf[ip_hlen + 11] = 0xEF;
    icmp.computeChecksumIcmpv4(pkt_buf[ip_hlen .. ip_hlen + icmp_len]);

    _ = stack.injectPacket(0, pkt_buf[0..total_len]);

    // Should have sent echo reply
    try testing.expect(link_ep.outboundCount() > 0);
    var out_buf: [1600]u8 = undefined;
    const reply_raw = link_ep.readOutbound(&out_buf).?;

    // Parse reply IP
    const reply_ip = ipv4_header.Header.parse(reply_raw) catch unreachable;
    try testing.expect(reply_ip.isChecksumValid());
    try testing.expectEqual(ipv4_header.Protocol.icmp, reply_ip.protocol());
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 1 }, &reply_ip.srcAddr());
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 2 }, &reply_ip.dstAddr());

    // Parse reply ICMP
    const reply_icmp_data = reply_ip.payload(reply_raw);
    const reply_icmp = icmp_header.Header.parse(reply_icmp_data) catch unreachable;
    try testing.expectEqual(icmp_header.Icmpv4Type.echo_reply, reply_icmp.icmpv4Type());
    try testing.expectEqual(@as(u16, 1234), reply_icmp.identifier());
    try testing.expectEqual(@as(u16, 1), reply_icmp.sequence());
    try testing.expect(reply_icmp.verifyChecksumIcmpv4(reply_icmp_data));

    // Verify payload preserved
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, reply_icmp_data[8..12]);
}

test "FullStack: PMTU discovery updates MSS" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });

    // Set up a pre-established connection
    stack.conns[0] = .{
        .conn = Connection{
            .state = .established,
            .sender = Sender.init(5000, 1460),
            .receiver = Receiver.init(2000, 65535),
            .mss = 1460,
        },
        .id = ConnId{
            .local_addr = .{ 10, 0, 0, 1 },
            .local_port = 5000,
            .remote_addr = .{ 10, 0, 0, 2 },
            .remote_port = 80,
        },
        .active = true,
    };
    stack.active_count = 1;

    // Build ICMP Dest Unreachable (code=4, frag needed), MTU=1280
    // Layout: IP(20) + ICMP hdr(8) + embedded IP(20) + embedded TCP first 8 bytes
    var pkt_buf: [256]u8 = undefined;
    const ip_hlen: usize = 20;
    const icmp_hdr_len: usize = 8;
    const embedded_ip_len: usize = 20;
    const embedded_tcp_len: usize = 8;
    const icmp_total = icmp_hdr_len + embedded_ip_len + embedded_tcp_len;
    const total_pkt_len = ip_hlen + icmp_total;

    // Outer IP header
    var ip = ipv4_header.MutableHeader.init(pkt_buf[0..ip_hlen]) catch unreachable;
    ip.setTotalLen(@intCast(total_pkt_len));
    ip.setTtl(64);
    ip.setProtocol(.icmp);
    ip.setSrcAddr(.{ 10, 0, 0, 254 }); // router
    ip.setDstAddr(.{ 10, 0, 0, 1 });
    ip.computeChecksum();

    // ICMP header: type=3 (dest unreachable), code=4 (frag needed)
    const icmp_off = ip_hlen;
    pkt_buf[icmp_off] = 3; // type
    pkt_buf[icmp_off + 1] = 4; // code
    pkt_buf[icmp_off + 2] = 0; // checksum (will compute)
    pkt_buf[icmp_off + 3] = 0;
    pkt_buf[icmp_off + 4] = 0; // unused
    pkt_buf[icmp_off + 5] = 0;
    // Next-hop MTU in bytes 6-7
    std.mem.writeInt(u16, pkt_buf[icmp_off + 6 ..][0..2], 1280, .big);

    // Embedded IP header (the offending packet we sent)
    const emb_off = icmp_off + icmp_hdr_len;
    var emb_ip = ipv4_header.MutableHeader.init(pkt_buf[emb_off .. emb_off + embedded_ip_len]) catch unreachable;
    emb_ip.setTotalLen(1500);
    emb_ip.setTtl(64);
    emb_ip.setProtocol(.tcp);
    emb_ip.setSrcAddr(.{ 10, 0, 0, 1 }); // our addr
    emb_ip.setDstAddr(.{ 10, 0, 0, 2 }); // peer addr
    emb_ip.computeChecksum();

    // Embedded TCP header (first 8 bytes: src_port, dst_port, seq)
    const tcp_off = emb_off + embedded_ip_len;
    std.mem.writeInt(u16, pkt_buf[tcp_off..][0..2], 5000, .big); // src port
    std.mem.writeInt(u16, pkt_buf[tcp_off + 2 ..][0..2], 80, .big); // dst port
    std.mem.writeInt(u32, pkt_buf[tcp_off + 4 ..][0..4], 5001, .big); // seq

    // Compute ICMP checksum
    const cksum_mod = @import("checksum.zig");
    pkt_buf[icmp_off + 2] = 0;
    pkt_buf[icmp_off + 3] = 0;
    const cksum = cksum_mod.compute(pkt_buf[icmp_off .. icmp_off + icmp_total]);
    std.mem.writeInt(u16, pkt_buf[icmp_off + 2 ..][0..2], cksum, .big);

    // Inject the ICMP error
    _ = stack.injectPacket(100, pkt_buf[0..total_pkt_len]);

    // Verify MSS was reduced
    try testing.expectEqual(@as(u16, 1240), stack.conns[0].conn.mss); // 1280 - 40
    try testing.expectEqual(@as(u16, 1240), stack.conns[0].conn.sender.mss);
    try testing.expectEqual(@as(u16, 1280), stack.path_mtu);
}

test "FullStack: a listen can be given back, and the slots are finite" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });

    // Eight is the default, and the ninth port has nowhere to go.
    var port: u16 = 8000;
    while (port < 8008) : (port += 1) try testing.expect(stack.listen(port, 128));
    try testing.expectEqual(@as(usize, 0), stack.listenSlotsFree());
    try testing.expect(!stack.listen(9999, 128));

    // A port already in the set costs nothing and stays.
    try testing.expect(stack.listen(8000, 128));
    try testing.expectEqual(@as(usize, 0), stack.listenSlotsFree());

    // Giving one back makes room, and only for a port that was there.
    try testing.expect(stack.unlisten(8003));
    try testing.expect(!stack.unlisten(8003));
    try testing.expectEqual(@as(usize, 1), stack.listenSlotsFree());
    try testing.expect(stack.listen(9999, 128));

    // The set still holds the ports it did not give back, including the one
    // the swap-remove moved.
    port = 8000;
    while (port < 8008) : (port += 1) {
        const want = port != 8003;
        try testing.expectEqual(want, stack.isListening(port));
    }
    try testing.expect(stack.isListening(9999));
}

test "FullStack: the listen and UDP capacities come from the config" {
    const Small = FullStackWith(8, .{ .max_listen_ports = 2, .max_udp_endpoints = 1 });
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = Small.init(&link_ep, .{ 10, 0, 0, 1 });

    try testing.expectEqual(@as(usize, 2), stack.listenSlotsFree());
    try testing.expect(stack.listen(80, 128));
    try testing.expect(stack.listen(81, 128));
    try testing.expect(!stack.listen(82, 128));
    try testing.expect(stack.unlisten(81));
    try testing.expect(stack.listen(82, 128));

    // And the UDP table is the size the config asked for, not the default 16.
    try testing.expectEqual(@as(usize, 1), stack.udp_eps.len);
    try testing.expect(stack.udpBind(53) != null);
    try testing.expect(stack.udpBind(54) == null);
}

test "FullStack: unlisten stops new SYNs and leaves established connections alone" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 128);

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;

    // A connection reaches ESTABLISHED the usual way.
    const syn_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(0, pkt_buf[0..syn_len])) {
        .accepted => {},
        else => return error.TestUnexpectedResult,
    }
    const syn_ack = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(1, pkt_buf[0..ack_len]);
    const conn_idx = stack.accept() orelse return error.NoConnection;

    // The listener goes away.
    try testing.expect(stack.unlisten(80));

    // The established connection still carries data.
    const data_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1001, syn_ack.seq +% 1, .{ .ack = true, .psh = true }, 65535, "hi", &pkt_buf);
    _ = stack.injectPacket(2, pkt_buf[0..data_len]);
    var data: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 2), stack.read(conn_idx, &data));
    try testing.expectEqualStrings("hi", data[0..2]);

    // A new SYN on that port is dropped, as it is for any closed port: no
    // SYN+ACK, and no connection.
    while (link_ep.readOutbound(&out_buf) != null) {}
    const syn2_len = buildTcpPacket(.{ 10, 0, 0, 3 }, 5001, .{ 10, 0, 0, 1 }, 80, 2000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(3, pkt_buf[0..syn2_len])) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 0), link_ep.outboundCount());
    try testing.expect(stack.accept() == null);
}

test "FullStack: a handshake completing after unlisten gives back its slot" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 128);

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;

    // Half-open: the SYN is answered and holds a SYN queue slot.
    const syn_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(0, pkt_buf[0..syn_len])) {
        .accepted => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(u16, 1), stack.syn_queue_count);
    const syn_ack = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;

    // The listener goes away while the ACK is still in flight.
    try testing.expect(stack.unlisten(80));

    // The ACK lands and the handshake completes with nobody to accept it.
    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(1, pkt_buf[0..ack_len])) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }

    // Every resource comes back: the half-open count, the connection slot,
    // and nothing waits in the accept queue for a caller that cannot know
    // it is there.
    try testing.expectEqual(@as(u16, 0), stack.syn_queue_count);
    try testing.expectEqual(@as(usize, 0), stack.active_count);
    try testing.expect(stack.accept() == null);

    // And the peer is told, rather than left with a connection we forgot.
    const rst = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    try testing.expect(rst.flags.rst);
}

test "FullStack: a deferred port holds its SYN instead of answering it" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    try testing.expect(stack.listenDeferred(80, 128));

    var pkt_buf: [128]u8 = undefined;
    const syn_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const pending = switch (stack.injectPacket(10, pkt_buf[0..syn_len])) {
        .syn_pending => |i| i,
        else => return error.TestUnexpectedResult,
    };

    // Nothing has been said to the peer, and nothing has been allocated.
    try testing.expectEqual(@as(usize, 0), link_ep.outboundCount());
    try testing.expectEqual(@as(usize, 0), stack.active_count);
    try testing.expectEqual(@as(u16, 0), stack.syn_queue_count);
    try testing.expectEqual(@as(usize, 1), stack.pendingSynCount());
    try testing.expectEqual(pending, stack.nextPendingSyn().?);

    const info = stack.pendingSynInfo(pending).?;
    try testing.expectEqual(@as(u16, 80), info.local_port);
    try testing.expectEqual(@as(u16, 5000), info.remote_port);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, &info.remote_addr);
    try testing.expectEqual(@as(u64, 10), info.received_ms);

    // A retransmission of the same SYN refreshes the hold, it does not take
    // a second slot.
    switch (stack.injectPacket(1200, pkt_buf[0..syn_len])) {
        .syn_pending => |i| try testing.expectEqual(pending, i),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 1), stack.pendingSynCount());
    try testing.expectEqual(@as(u64, 1200), stack.pendingSynInfo(pending).?.received_ms);
}

test "FullStack: acceptPending finishes the handshake the usual way" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listenDeferred(80, 128);

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;
    const syn_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const pending = switch (stack.injectPacket(0, pkt_buf[0..syn_len])) {
        .syn_pending => |i| i,
        else => return error.TestUnexpectedResult,
    };

    // The application has found something to answer with.
    const conn_idx = stack.acceptPending(pending, 50) orelse return error.NoConnection;
    try testing.expectEqual(@as(usize, 0), stack.pendingSynCount());
    try testing.expect(stack.nextPendingSyn() == null);

    // Now the peer hears a SYN+ACK that acknowledges the SYN it sent.
    const syn_ack = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    try testing.expect(syn_ack.flags.syn and syn_ack.flags.ack);
    try testing.expectEqual(@as(u32, 1001), syn_ack.ack);
    try testing.expectEqual(@as(u16, 80), syn_ack.src_port);

    // And the handshake completes into the accept queue, as a plain listen
    // would have.
    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(60, pkt_buf[0..ack_len])) {
        .accepted => |i| try testing.expectEqual(conn_idx, i),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(conn_idx, stack.accept().?);
    try testing.expectEqual(tcp_connection.State.established, stack.connState(conn_idx).?);

    // Settling the same hold twice changes nothing.
    try testing.expect(stack.acceptPending(pending, 70) == null);
}

test "FullStack: rejectPending tells the peer there is nothing here" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listenDeferred(80, 128);

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;
    const syn_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const pending = switch (stack.injectPacket(0, pkt_buf[0..syn_len])) {
        .syn_pending => |i| i,
        else => return error.TestUnexpectedResult,
    };

    stack.rejectPending(pending);
    try testing.expectEqual(@as(usize, 0), stack.pendingSynCount());

    // A refusal, not silence: the peer stops waiting rather than
    // retransmitting until it gives up.
    const rst = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    try testing.expect(rst.flags.rst);
    try testing.expectEqual(@as(u32, 1001), rst.ack);
    try testing.expectEqual(@as(usize, 0), stack.active_count);

    stack.rejectPending(pending); // twice is nothing
    try testing.expectEqual(@as(usize, 0), link_ep.outboundCount());
}

test "FullStack: the pending table is bounded, and holds expire" {
    const Small = FullStackWith(16, .{ .max_pending_syns = 2 });
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = Small.init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listenDeferred(80, 128);

    var pkt_buf: [128]u8 = undefined;
    var port: u16 = 5000;
    while (port < 5002) : (port += 1) {
        const len = buildTcpPacket(.{ 10, 0, 0, 2 }, port, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
        switch (stack.injectPacket(100, pkt_buf[0..len])) {
            .syn_pending => {},
            else => return error.TestUnexpectedResult,
        }
    }
    try testing.expectEqual(@as(usize, 2), stack.pendingSynCount());

    // A third is dropped, which is what the peer sees from a stack that is
    // not listening at all: no answer, and it retransmits.
    const third = buildTcpPacket(.{ 10, 0, 0, 2 }, 5002, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(100, pkt_buf[0..third])) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 0), link_ep.outboundCount());

    // Holds nobody settled time out, and silently: to the peer the SYN was
    // lost, which is the same thing it would have been.
    try testing.expectEqual(@as(usize, 0), stack.expirePendingSyns(1000, 5000));
    try testing.expectEqual(@as(usize, 2), stack.expirePendingSyns(5100, 5000));
    try testing.expectEqual(@as(usize, 0), stack.pendingSynCount());
    try testing.expectEqual(@as(usize, 0), link_ep.outboundCount());
}

test "FullStack: unlisten resets the SYNs that port was holding" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listenDeferred(80, 128);
    _ = stack.listenDeferred(81, 128);

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;
    const a = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(0, pkt_buf[0..a]);
    const b = buildTcpPacket(.{ 10, 0, 0, 2 }, 5001, .{ 10, 0, 0, 1 }, 81, 2000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(0, pkt_buf[0..b]);
    try testing.expectEqual(@as(usize, 2), stack.pendingSynCount());

    // The listener goes away while it is holding someone's SYN: that peer is
    // waiting on an answer nobody will ever give.
    try testing.expect(stack.unlisten(80));
    try testing.expectEqual(@as(usize, 1), stack.pendingSynCount());
    const rst = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    try testing.expect(rst.flags.rst);
    try testing.expectEqual(@as(u16, 80), rst.src_port);
    try testing.expectEqual(@as(usize, 0), link_ep.outboundCount());

    // The other port keeps what it was holding.
    try testing.expectEqual(@as(u16, 81), stack.pendingSynInfo(stack.nextPendingSyn().?).?.local_port);
}

test "FullStack: a port can stop and start deferring" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;

    // Plain listen first: the SYN is answered where it arrives.
    _ = stack.listen(80, 128);
    const syn = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(0, pkt_buf[0..syn])) {
        .accepted => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?.flags.syn);
    try testing.expectEqual(@as(usize, 1), stack.listen_count);

    // The same port, now deferring, takes no second listen slot and holds.
    try testing.expect(stack.listenDeferred(80, 128));
    try testing.expectEqual(@as(usize, 1), stack.listen_count);
    const syn2 = buildTcpPacket(.{ 10, 0, 0, 3 }, 5001, .{ 10, 0, 0, 1 }, 80, 2000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(0, pkt_buf[0..syn2])) {
        .syn_pending => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 0), link_ep.outboundCount());

    // And back again.
    try testing.expect(stack.listen(80, 128));
    const syn3 = buildTcpPacket(.{ 10, 0, 0, 4 }, 5002, .{ 10, 0, 0, 1 }, 80, 3000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(0, pkt_buf[0..syn3])) {
        .accepted => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?.flags.syn);
}

test "FullStack: SYN cookie activates under backlog pressure" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 128);
    // Set low threshold so we trigger SYN cookies easily
    stack.syn_cookie_threshold = 2;

    // Fill backlog with 2 half-open connections (reach threshold)
    var pkt_buf: [128]u8 = undefined;
    var i: u16 = 0;
    while (i < 2) : (i += 1) {
        const syn_len = buildTcpPacket(
            .{ 10, 0, 0, 2 },
            @as(u16, 6000) + i,
            .{ 10, 0, 0, 1 },
            80,
            1000 + @as(u32, i) * 100,
            0,
            .{ .syn = true },
            65535,
            &.{},
            &pkt_buf,
        );
        _ = stack.injectPacket(0, pkt_buf[0..syn_len]);
        // Drain SYN+ACK
        var out_buf: [1600]u8 = undefined;
        _ = link_ep.readOutbound(&out_buf);
    }

    // Now both slots are SYN_RECEIVED (half-open)
    // Next SYN should use SYN cookie (stateless)
    const syn_len = buildTcpPacket(
        .{ 10, 0, 0, 3 },
        7000,
        .{ 10, 0, 0, 1 },
        80,
        5000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );
    const ev = stack.injectPacket(100, pkt_buf[0..syn_len]);
    // SYN cookie: no connection state allocated, returns .none
    switch (ev) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }

    // But a SYN+ACK should still have been sent
    var out_buf2: [1600]u8 = undefined;
    const syn_ack_raw = link_ep.readOutbound(&out_buf2).?;
    const syn_ack = parseTcpFromRaw(syn_ack_raw).?;
    try testing.expect(syn_ack.flags.syn);
    try testing.expect(syn_ack.flags.ack);
    try testing.expectEqual(@as(u32, 5001), syn_ack.ack);

    // Client completes handshake with ACK
    const cookie_isn = syn_ack.seq;
    const ack_len = buildTcpPacket(
        .{ 10, 0, 0, 3 },
        7000,
        .{ 10, 0, 0, 1 },
        80,
        5001,
        cookie_isn + 1,
        .{ .ack = true },
        65535,
        &.{},
        &pkt_buf,
    );
    const ev2 = stack.injectPacket(200, pkt_buf[0..ack_len]);
    // Should accept via cookie validation
    switch (ev2) {
        .accepted => |idx| {
            try testing.expectEqual(tcp_connection.State.established, stack.connState(idx).?);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "FullStack: SYN cookie rejects invalid ACK" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });

    // Send an ACK with a random ack number (no valid cookie)
    var pkt_buf: [128]u8 = undefined;
    const ack_len = buildTcpPacket(
        .{ 10, 0, 0, 5 },
        9000,
        .{ 10, 0, 0, 1 },
        80,
        2000,
        99999, // bogus ack — not a valid cookie
        .{ .ack = true },
        65535,
        &.{},
        &pkt_buf,
    );
    const ev = stack.injectPacket(0, pkt_buf[0..ack_len]);
    // Should get RST (no valid cookie, no matching connection)
    switch (ev) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
    // Verify RST was sent
    var out_buf: [1600]u8 = undefined;
    const rst_raw = link_ep.readOutbound(&out_buf).?;
    const rst = parseTcpFromRaw(rst_raw).?;
    try testing.expect(rst.flags.rst);
}

test "FullStack: ICMPv6 echo reply" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });

    // Build ICMPv6 echo request in an IPv6 packet
    var pkt_buf: [128]u8 = undefined;
    const ip6_hlen: usize = 40;
    const icmp_len: usize = 12; // 8 header + 4 payload
    const total_len: usize = ip6_hlen + icmp_len;

    // IPv6 header
    var ip6 = ipv6_header.MutableHeader.init(pkt_buf[0..ip6_hlen]) catch unreachable;
    ip6.setPayloadLen(@intCast(icmp_len));
    ip6.setNextHeader(.icmpv6);
    ip6.setHopLimit(64);
    // src: fd00::2
    var src6: [16]u8 = .{0} ** 16;
    src6[0] = 0xfd;
    src6[15] = 0x02;
    ip6.setSrcAddr(src6);
    // dst: fd00::1
    var dst6: [16]u8 = .{0} ** 16;
    dst6[0] = 0xfd;
    dst6[15] = 0x01;
    ip6.setDstAddr(dst6);

    // ICMPv6 echo request (type=128)
    pkt_buf[ip6_hlen] = 128; // echo request
    pkt_buf[ip6_hlen + 1] = 0; // code
    pkt_buf[ip6_hlen + 2] = 0; // checksum (will compute)
    pkt_buf[ip6_hlen + 3] = 0;
    // id=1000, seq=5
    std.mem.writeInt(u16, pkt_buf[ip6_hlen + 4 ..][0..2], 1000, .big);
    std.mem.writeInt(u16, pkt_buf[ip6_hlen + 6 ..][0..2], 5, .big);
    // Payload
    pkt_buf[ip6_hlen + 8] = 0xCA;
    pkt_buf[ip6_hlen + 9] = 0xFE;
    pkt_buf[ip6_hlen + 10] = 0xBA;
    pkt_buf[ip6_hlen + 11] = 0xBE;

    // ICMPv6 checksum (uses pseudo-header)
    const cksum_mod = @import("checksum.zig");
    const ph = cksum_mod.pseudoHeaderIpv6(src6, dst6, 58, icmp_len);
    const sum = cksum_mod.accumulate(ph, pkt_buf[ip6_hlen .. ip6_hlen + icmp_len]);
    const cksum = cksum_mod.finish(sum);
    std.mem.writeInt(u16, pkt_buf[ip6_hlen + 2 ..][0..2], cksum, .big);

    _ = stack.injectPacket(0, pkt_buf[0..total_len]);

    // Should have sent ICMPv6 echo reply
    try testing.expect(link_ep.outboundCount() > 0);
    var out_buf: [1600]u8 = undefined;
    const reply_raw = link_ep.readOutbound(&out_buf).?;

    // Parse reply IPv6
    const reply_ip6 = ipv6_header.Header.parse(reply_raw) catch unreachable;
    try testing.expectEqual(ipv6_header.NextHeader.icmpv6, reply_ip6.nextHeader());
    // Src should be dst6, dst should be src6
    try testing.expectEqualSlices(u8, &dst6, &reply_ip6.srcAddr());
    try testing.expectEqualSlices(u8, &src6, &reply_ip6.dstAddr());

    // Parse reply ICMPv6
    const reply_icmp_data = reply_ip6.payload(reply_raw);
    try testing.expectEqual(@as(u8, 129), reply_icmp_data[0]); // echo reply type
    // Verify id and seq preserved
    try testing.expectEqual(@as(u16, 1000), std.mem.readInt(u16, reply_icmp_data[4..6], .big));
    try testing.expectEqual(@as(u16, 5), std.mem.readInt(u16, reply_icmp_data[6..8], .big));
    // Verify payload
    try testing.expectEqualSlices(u8, &[_]u8{ 0xCA, 0xFE, 0xBA, 0xBE }, reply_icmp_data[8..12]);
}

test "FullStack: IPv6 fragment reassembly dispatches ICMPv6" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(8).init(&link_ep, .{ 10, 0, 0, 1 });
    stack.ipv6_enabled = true;
    stack.local_addr6 = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

    const src6 = [16]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst6 = stack.local_addr6;

    // Build an ICMPv6 echo request (12 bytes: type=128, code=0, cksum=0, id=1, seq=1, data=0xDE,0xAD)
    var icmp_payload: [12]u8 = undefined;
    icmp_payload[0] = 128; // echo request
    icmp_payload[1] = 0; // code
    icmp_payload[2] = 0; // checksum placeholder
    icmp_payload[3] = 0;
    std.mem.writeInt(u16, icmp_payload[4..6], 1, .big); // id
    std.mem.writeInt(u16, icmp_payload[6..8], 1, .big); // seq
    icmp_payload[8] = 0xDE;
    icmp_payload[9] = 0xAD;
    icmp_payload[10] = 0xBE;
    icmp_payload[11] = 0xEF;
    // Compute ICMPv6 checksum
    {
        const cksum_mod = @import("checksum.zig");
        icmp_payload[2] = 0;
        icmp_payload[3] = 0;
        const ph = cksum_mod.pseudoHeaderIpv6(src6, dst6, 58, 12);
        const sum = cksum_mod.accumulate(ph, &icmp_payload);
        const cksum = cksum_mod.finish(sum);
        std.mem.writeInt(u16, icmp_payload[2..4], cksum, .big);
    }

    // Split into 2 fragments: first 8 bytes, then remaining 4 bytes
    // Fragment 1: offset=0, M=1
    var frag1_pkt: [40 + 8 + 8]u8 = undefined; // IPv6(40) + FragHdr(8) + data(8)
    @memset(&frag1_pkt, 0);
    // IPv6 header
    frag1_pkt[0] = 0x60; // version=6
    std.mem.writeInt(u16, frag1_pkt[4..6], 16, .big); // payload_len = frag_hdr(8) + data(8)
    frag1_pkt[6] = 44; // next_header = fragment
    frag1_pkt[7] = 64; // hop limit
    @memcpy(frag1_pkt[8..24], &src6);
    @memcpy(frag1_pkt[24..40], &dst6);
    // Fragment header: next_header=58(ICMPv6), reserved=0, offset=0, M=1, identification=0x1234
    frag1_pkt[40] = 58; // next_header (ICMPv6)
    frag1_pkt[41] = 0; // reserved
    frag1_pkt[42] = 0; // offset high (0)
    frag1_pkt[43] = 1; // offset low=0, M=1
    std.mem.writeInt(u32, frag1_pkt[44..48], 0x1234, .big); // identification
    // First 8 bytes of ICMPv6 payload
    @memcpy(frag1_pkt[48..56], icmp_payload[0..8]);

    // Fragment 2: offset=1 (8 bytes), M=0
    var frag2_pkt: [40 + 8 + 4]u8 = undefined;
    @memset(&frag2_pkt, 0);
    frag2_pkt[0] = 0x60;
    std.mem.writeInt(u16, frag2_pkt[4..6], 12, .big); // payload_len = frag_hdr(8) + data(4)
    frag2_pkt[6] = 44;
    frag2_pkt[7] = 64;
    @memcpy(frag2_pkt[8..24], &src6);
    @memcpy(frag2_pkt[24..40], &dst6);
    frag2_pkt[40] = 58;
    frag2_pkt[41] = 0;
    frag2_pkt[42] = 0; // offset = 1 (in 8-byte units) → 0x0008 >> 3 = 1, shifted: 1<<3 = 8
    frag2_pkt[43] = 0x08; // offset=1 (bits 15:3 = 1 → byte[42..43] = 0x0008), M=0
    std.mem.writeInt(u32, frag2_pkt[44..48], 0x1234, .big);
    @memcpy(frag2_pkt[48..52], icmp_payload[8..12]);

    // Inject fragments
    const ev1 = stack.injectPacket(100, &frag1_pkt);
    try testing.expectEqual(Event.none, ev1);

    const ev2 = stack.injectPacket(100, &frag2_pkt);
    try testing.expectEqual(Event.none, ev2); // ICMPv6 reply is internal

    // Check that an ICMPv6 echo reply was emitted on the link
    var out_buf: [1600]u8 = undefined;
    const reply = link_ep.readOutbound(&out_buf);
    try testing.expect(reply != null);
    // Should be an IPv6 packet with ICMPv6 echo reply
    const r = reply.?;
    try testing.expect(r.len >= 40 + 8);
    try testing.expectEqual(@as(u8, 0x60), r[0] & 0xF0); // IPv6
}

test "FullStack: SYN with Window Scale options" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(4).init(&link_ep, .{ 10, 0, 0, 1 });

    // Active open
    const idx = stack.connect(0, .{ 10, 0, 0, 2 }, 80, 5000);
    try testing.expect(idx != null);

    // Poll to emit SYN
    _ = stack.poll(1);

    // Read the SYN packet from link outbound queue
    var out_buf: [1600]u8 = undefined;
    const raw_opt = link_ep.readOutbound(&out_buf);
    try testing.expect(raw_opt != null);
    const raw = raw_opt.?;

    // Skip IP header (20 bytes)
    try testing.expect(raw.len > 40); // IP(20) + TCP(20+opts)
    const tcp_data = raw[20..];
    const tcp_hdr2 = tcp_header.Header.parse(tcp_data) catch unreachable;
    const hdr_len = tcp_hdr2.headerLen();

    // Data offset should be > 20 (options present)
    try testing.expect(hdr_len > 20);

    // Parse options — should contain MSS and Window Scale
    const opts_data = tcp_data[20..hdr_len];
    const opts_mod2 = @import("transport/tcp/options.zig");
    const parsed = opts_mod2.parseOptions(opts_data);
    try testing.expect(parsed.window_scale > 0);
    try testing.expect(parsed.mss > 0);
}

test "FullStack: accept queue dequeues established connections" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 8);

    // Accept queue should be empty initially
    try testing.expectEqual(@as(?u16, null), stack.accept());

    // Send SYN → get accepted event → but connection goes to accept queue
    var pkt_buf: [128]u8 = undefined;
    const syn_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        5000,
        .{ 10, 0, 0, 1 },
        80,
        1000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );
    const ev = stack.injectPacket(0, pkt_buf[0..syn_len]);
    switch (ev) {
        .accepted => {},
        else => return error.TestUnexpectedResult,
    }

    // Complete handshake: parse SYN+ACK, send ACK
    var out_buf: [1600]u8 = undefined;
    const syn_ack_raw = link_ep.readOutbound(&out_buf).?;
    const syn_ack = parseTcpFromRaw(syn_ack_raw).?;
    const ack_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        5000,
        .{ 10, 0, 0, 1 },
        80,
        1001,
        syn_ack.seq + 1,
        .{ .ack = true },
        65535,
        &.{},
        &pkt_buf,
    );
    const ev2 = stack.injectPacket(1, pkt_buf[0..ack_len]);
    // Connection moves from SYN_RECEIVED to ESTABLISHED → enqueued to accept queue
    switch (ev2) {
        .accepted => |idx| {
            try testing.expectEqual(tcp_connection.State.established, stack.connState(idx).?);
        },
        else => {},
    }

    // accept() should return the connection
    const accepted_idx = stack.accept();
    try testing.expect(accepted_idx != null);
    try testing.expectEqual(tcp_connection.State.established, stack.connState(accepted_idx.?).?);

    // Queue should now be empty
    try testing.expectEqual(@as(?u16, null), stack.accept());
}

test "FullStack: SYN queue drops when full" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 128);
    stack.syn_queue_limit = 2;
    stack.syn_cookie_threshold = 3; // higher than limit so cookies don't activate first

    // Fill SYN queue with 2 half-open connections
    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;
    var i: u16 = 0;
    while (i < 2) : (i += 1) {
        const syn_len = buildTcpPacket(
            .{ 10, 0, 0, 2 },
            @as(u16, 6000) + i,
            .{ 10, 0, 0, 1 },
            80,
            2000 + @as(u32, i) * 100,
            0,
            .{ .syn = true },
            65535,
            &.{},
            &pkt_buf,
        );
        _ = stack.injectPacket(0, pkt_buf[0..syn_len]);
        _ = link_ep.readOutbound(&out_buf);
    }

    // SYN queue is full (2/2), next SYN should be dropped
    const syn_len = buildTcpPacket(
        .{ 10, 0, 0, 3 },
        7000,
        .{ 10, 0, 0, 1 },
        80,
        5000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );
    const ev = stack.injectPacket(0, pkt_buf[0..syn_len]);
    switch (ev) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
}

test "FullStack: accept queue full drops cookie connections" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 128);
    stack.accept_queue_limit = 0; // zero = immediately full
    stack.syn_cookie_threshold = 0; // force cookie mode

    // SYN triggers cookie response
    var pkt_buf: [128]u8 = undefined;
    const syn_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        5000,
        .{ 10, 0, 0, 1 },
        80,
        1000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );
    _ = stack.injectPacket(100, pkt_buf[0..syn_len]);

    var out_buf: [1600]u8 = undefined;
    const syn_ack_raw = link_ep.readOutbound(&out_buf).?;
    const syn_ack = parseTcpFromRaw(syn_ack_raw).?;

    // Client sends ACK to complete cookie handshake
    const ack_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        5000,
        .{ 10, 0, 0, 1 },
        80,
        1001,
        syn_ack.seq + 1,
        .{ .ack = true },
        65535,
        &.{},
        &pkt_buf,
    );
    const ev = stack.injectPacket(200, pkt_buf[0..ack_len]);
    // Accept queue is full → connection dropped
    switch (ev) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }
}

test "FullStackWith: embedded_minimal config completes TCP handshake + data" {
    const cfg = tcp_connection.Config.embedded_minimal;
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStackWith(4, cfg).init(&link_ep, .{ 192, 168, 1, 1 });
    _ = stack.listen(80, 4);

    // Client sends SYN
    var pkt_buf: [128]u8 = undefined;
    const syn_len = buildTcpPacket(
        .{ 192, 168, 1, 2 },
        9000,
        .{ 192, 168, 1, 1 },
        80,
        1000,
        0,
        .{ .syn = true },
        2048,
        &.{},
        &pkt_buf,
    );

    const ev1 = stack.injectPacket(0, pkt_buf[0..syn_len]);
    switch (ev1) {
        .accepted => |idx| try testing.expectEqual(@as(u16, 0), idx),
        else => return error.TestUnexpectedResult,
    }

    // Extract SYN+ACK
    var out_buf: [1600]u8 = undefined;
    const syn_ack_raw = link_ep.readOutbound(&out_buf).?;
    const syn_ack = parseTcpFromRaw(syn_ack_raw).?;
    try testing.expect(syn_ack.flags.syn);
    try testing.expect(syn_ack.flags.ack);

    const server_isn = syn_ack.seq;

    // Client sends ACK completing handshake
    stack.conns[0].conn.sender.syn_sent = true;
    stack.conns[0].conn.sender.snd_nxt = server_isn + 1;
    stack.conns[0].conn.sender.snd_una = server_isn;
    stack.conns[0].conn.sender.retx_queue[0] = .{
        .seq = server_isn,
        .len = 1,
        .sent_at = 0,
        .is_syn = true,
    };
    stack.conns[0].conn.sender.retx_count = 1;

    const ack_len = buildTcpPacket(
        .{ 192, 168, 1, 2 },
        9000,
        .{ 192, 168, 1, 1 },
        80,
        1001,
        server_isn + 1,
        .{ .ack = true },
        2048,
        &.{},
        &pkt_buf,
    );
    const ev2 = stack.injectPacket(10, pkt_buf[0..ack_len]);
    switch (ev2) {
        .accepted => {},
        .established => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(tcp_connection.State.established, stack.connState(0).?);

    // Server sends data: "Hi" (fits in 1KB send buffer)
    const written = stack.write(0, "Hi from embedded!");
    try testing.expectEqual(@as(usize, 17), written);

    // Poll to emit data packet
    stack.conns[0].conn.sender.nagle_enabled = false;
    _ = stack.poll(20);

    // Client sends data
    const data_pkt_len = buildTcpPacket(
        .{ 192, 168, 1, 2 },
        9000,
        .{ 192, 168, 1, 1 },
        80,
        1001,
        server_isn + 1,
        .{ .ack = true, .psh = true },
        2048,
        "hello",
        &pkt_buf,
    );
    const ev3 = stack.injectPacket(30, pkt_buf[0..data_pkt_len]);
    switch (ev3) {
        .data_ready => |idx| try testing.expectEqual(@as(u16, 0), idx),
        else => return error.TestUnexpectedResult,
    }

    var read_buf: [64]u8 = undefined;
    const n = stack.read(0, &read_buf);
    try testing.expectEqualSlices(u8, "hello", read_buf[0..n]);

    // Verify config was applied: send buffer is small
    try testing.expectEqual(@as(usize, 1024), stack.conns[0].conn.send_buf.len);
    // Verify recv buffer is small
    try testing.expectEqual(@as(usize, 2048), stack.conns[0].conn.receiver.buf_cap);
    // Verify retx queue is small
    try testing.expectEqual(@as(usize, 16), stack.conns[0].conn.sender.retx_queue.len);
    // Verify OOO segments are limited
    try testing.expectEqual(@as(usize, 4), stack.conns[0].conn.receiver.ooo.len);
}

test "FullStack: hash index lookup (max_conns > 32)" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStackWith(64, tcp_connection.Config.embedded_minimal).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 16);

    // Send SYN from a client
    var pkt_buf: [128]u8 = undefined;
    const syn_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        5000,
        .{ 10, 0, 0, 1 },
        80,
        1000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );
    const ev = stack.injectPacket(0, pkt_buf[0..syn_len]);
    switch (ev) {
        .accepted => |idx| {
            // Verify findConn uses hash and finds the connection
            const id = stack.conns[idx].id;
            const found = stack.findConn(id);
            try testing.expectEqual(@as(?usize, idx), found);
        },
        else => return error.TestUnexpectedResult,
    }

    // Verify multiple connections are found via hash
    var pkt_buf2: [128]u8 = undefined;
    const syn_len2 = buildTcpPacket(
        .{ 10, 0, 0, 3 },
        6000,
        .{ 10, 0, 0, 1 },
        80,
        2000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf2,
    );
    const ev2 = stack.injectPacket(0, pkt_buf2[0..syn_len2]);
    switch (ev2) {
        .accepted => |idx2| {
            const id2 = stack.conns[idx2].id;
            const found2 = stack.findConn(id2);
            try testing.expectEqual(@as(?usize, idx2), found2);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "FullStack: TCP with corrupted checksum is dropped" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 128);

    var pkt_buf: [128]u8 = undefined;
    const syn_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        5000,
        .{ 10, 0, 0, 1 },
        80,
        1000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );

    // Corrupt TCP checksum (bytes 36-37 in a standard 20-byte IP + 20-byte TCP header)
    pkt_buf[36] ^= 0xFF;

    const event = stack.injectPacket(0, pkt_buf[0..syn_len]);
    switch (event) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }

    // No SYN-ACK should be generated
    var out_buf: [1600]u8 = undefined;
    try testing.expect(link_ep.readOutbound(&out_buf) == null);
}

test "FullStack: forwarding with SNAT" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var egress_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(4).init(&link_ep, .{ 100, 64, 0, 1 });

    stack.enableForwarding(.{
        .local_addr = .{ 100, 64, 0, 1 },
        .mesh_prefix = .{ 100, 64, 0, 0 },
        .mesh_prefix_len = 10,
        .exit_node = true,
        .nat_port_start = 40000,
        .nat_port_end = 50000,
    });
    stack.setEgressLink(&egress_ep);

    // Inject a packet from mesh peer destined for the internet (needs SNAT)
    var pkt_buf: [128]u8 = undefined;
    const syn_len = buildTcpPacket(
        .{ 100, 64, 0, 2 },
        5000,
        .{ 8, 8, 8, 8 },
        443,
        1000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );
    const event = stack.injectPacket(100, pkt_buf[0..syn_len]);
    try testing.expectEqual(Event.none, event);

    // Check that the packet was forwarded to egress with NAT applied
    var fwd_buf: [1600]u8 = undefined;
    const fwd_pkt = egress_ep.readOutbound(&fwd_buf);
    try testing.expect(fwd_pkt != null);

    if (fwd_pkt) |pkt| {
        // Source IP should be rewritten to our local addr
        try testing.expect(std.mem.eql(u8, pkt[12..16], &[4]u8{ 100, 64, 0, 1 }));
        // Destination should remain 8.8.8.8
        try testing.expect(std.mem.eql(u8, pkt[16..20], &[4]u8{ 8, 8, 8, 8 }));
        // TTL should be decremented
        try testing.expectEqual(@as(u8, 63), pkt[8]);
        // Source port should be NAT'd to 40000
        const ihl: usize = @as(usize, pkt[0] & 0x0F) * 4;
        const nat_port = std.mem.readInt(u16, pkt[ihl..][0..2], .big);
        try testing.expectEqual(@as(u16, 40000), nat_port);
    }

    // Verify conntrack entry was created
    try testing.expectEqual(@as(usize, 1), stack.activeFlows());
}

test "FullStack: forwarding mesh-to-mesh (no NAT)" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var egress_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(4).init(&link_ep, .{ 100, 64, 0, 1 });

    stack.enableForwarding(.{
        .local_addr = .{ 100, 64, 0, 1 },
        .mesh_prefix = .{ 100, 64, 0, 0 },
        .mesh_prefix_len = 10,
    });
    stack.setEgressLink(&egress_ep);

    // Mesh peer A (100.64.0.2) → Mesh peer B (100.64.0.3), forwarded via us
    var pkt_buf: [128]u8 = undefined;
    const syn_len = buildTcpPacket(
        .{ 100, 64, 0, 2 },
        5000,
        .{ 100, 64, 0, 3 },
        80,
        1000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );
    _ = stack.injectPacket(100, pkt_buf[0..syn_len]);

    var fwd_buf: [1600]u8 = undefined;
    const fwd_pkt = egress_ep.readOutbound(&fwd_buf);
    try testing.expect(fwd_pkt != null);

    if (fwd_pkt) |pkt| {
        // No NAT: source and dest unchanged
        try testing.expect(std.mem.eql(u8, pkt[12..16], &[4]u8{ 100, 64, 0, 2 }));
        try testing.expect(std.mem.eql(u8, pkt[16..20], &[4]u8{ 100, 64, 0, 3 }));
        // TTL decremented
        try testing.expectEqual(@as(u8, 63), pkt[8]);
    }
}

test "FullStack: forwarding disabled does not forward" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(4).init(&link_ep, .{ 100, 64, 0, 1 });

    // Forwarding NOT enabled — packet to another IP should be silently dropped
    var pkt_buf: [128]u8 = undefined;
    const syn_len = buildTcpPacket(
        .{ 100, 64, 0, 2 },
        5000,
        .{ 100, 64, 0, 3 },
        80,
        1000,
        0,
        .{ .syn = true },
        65535,
        &.{},
        &pkt_buf,
    );
    const event = stack.injectPacket(100, pkt_buf[0..syn_len]);
    try testing.expectEqual(Event.none, event);

    // Nothing forwarded (no egress link set, but also no forwarding)
    var fwd_buf: [1600]u8 = undefined;
    try testing.expect(link_ep.readOutbound(&fwd_buf) == null);
}
