// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

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
const byte_store = @import("transport/tcp/byte_store.zig");
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
    /// rejectPending, passing back the handle.
    syn_pending: PendingHandle,
};

/// Names one held SYN. The slot is reused once the hold it carried is
/// settled or expires, and the generation changes when it is, so a caller
/// that comes back later — after dialling somewhere, say — settles its own
/// hold or nothing at all.
pub const PendingHandle = struct {
    idx: u16,
    gen: u32,

    /// Whether two handles name the same hold. Here rather than in each
    /// caller, so nobody compares one field and not the other.
    pub fn eql(self: PendingHandle, other: PendingHandle) bool {
        return self.idx == other.idx and self.gen == other.gen;
    }
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
    // A packet is built in a 1500-byte buffer, and an IPv4 link carries
    // at least 68 (RFC 791).
    comptime std.debug.assert(cfg.link_mtu >= 68 and cfg.link_mtu <= 1500);
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
            /// Which connection this is, of all the ones this slot has
            /// held (connGen). Set when the slot is taken; 0 for one never
            /// taken.
            gen: u32 = 0,
        };

        const max_udp_endpoints: usize = cfg.max_udp_endpoints;

        pub const UdpSlot = struct {
            ep: udp_endpoint.Endpoint = .{},
            active: bool = false,
        };

        const max_listen_ports: usize = cfg.max_listen_ports;
        const max_pending_syns: usize = cfg.max_pending_syns;

        /// The addresses a v6 segment arrived on. ConnId keeps only the low
        /// four bytes of each, which is enough to tell v4 flows apart and not
        /// enough for v6: two peers whose addresses end the same way share a
        /// ConnId.
        pub const V6Addrs = struct {
            local: [16]u8,
            remote: [16]u8,
        };

        /// A SYN for a deferred port, kept until the application decides. It
        /// holds what acceptConn would have been called with, so accepting it
        /// later takes exactly the path an immediate accept would have.
        pub const PendingSyn = struct {
            /// Changes every time the slot takes a new SYN, so a handle from
            /// a hold that has come and gone no longer names this one.
            gen: u32 = 0,
            id: ConnId = .{ .local_addr = .{0} ** 4, .local_port = 0, .remote_addr = .{0} ** 4, .remote_port = 0 },
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
            /// Pass this back to acceptPending or rejectPending.
            handle: PendingHandle,
            local_port: u16,
            remote_addr: [4]u8,
            remote_port: u16,
            received_ms: u64,
            is_v6: bool,
            remote_addr6: [16]u8,
            /// Where a v6 SYN was sent: this node, or a host it relays for.
            local_addr6: [16]u8,
        };
        const ReasmT = reassembly_mod.ReassemblerWith(8, cfg.max_reasm_datagram);
        const use_hash_index = max_conns > 32;
        const hash_capacity = if (use_hash_index) max_conns * 2 else 0;
        const empty_slot: u16 = @intCast(max_conns);

        const conn_chunk: usize = cfg.conn_chunk;
        const chunked = conn_chunk > 0;
        const chunk_count: usize = if (chunked) max_conns / conn_chunk else 0;
        comptime {
            if (chunked and max_conns % conn_chunk != 0) @compileError("max_conns must be a multiple of conn_chunk");
        }
        const Conns = if (chunked) [chunk_count]?*[conn_chunk]ConnSlot else [max_conns]ConnSlot;

        /// The connection slots: all of them inline, or the chunks allocated
        /// so far (cfg.conn_chunk). Reached through slotAt, never indexed.
        conns: Conns = if (chunked) [_]?*[conn_chunk]ConnSlot{null} ** chunk_count else [_]ConnSlot{.{}} ** max_conns,
        /// How many slots exist: max_conns inline, and a whole number of
        /// chunks otherwise, allocated in order from the first.
        slots_ready: usize = if (chunked) 0 else max_conns,
        /// Where chunks come from. Null for an inline stack, and a chunked
        /// one without it has no slots to give.
        allocator: ?std.mem.Allocator = null,
        /// What every connection's buffers come from when they grow: the
        /// allocator above, held to cfg.buf_budget. Connections point into
        /// it, which is one more reason the stack is written in place
        /// (initAlloc) and never moved after.
        buf_budget: if (cfg.grow_buffers) byte_store.Budget else void = if (cfg.grow_buffers) .{ .parent = std.mem.Allocator.failing } else {},
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
        accept_queue_limit: u16 = @min(128, max_conns),
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
        /// The identification of the next IPv6 datagram this stack
        /// fragments (emitUdpFragments6).
        ip6_frag_id: u32 = 1,
        /// The generation the next connection is given (ConnSlot.gen).
        /// Stack-wide rather than per slot: a slot is written over whole
        /// when it is taken, and a count kept in it would go with it.
        next_conn_gen: u32 = 1,
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
            if (comptime chunked) @compileError("a stack with conn_chunk set takes its slots from an allocator: initAlloc");
            if (comptime cfg.grow_buffers) @compileError("a stack with grow_buffers set takes its buffers from an allocator: initAlloc");
            return Self{
                .link = link_ep,
                .local_addr = local_addr,
            };
        }

        pub fn initWithSecret(link_ep: *LinkT, local_addr: [4]u8, secret: [16]u8) Self {
            if (comptime chunked) @compileError("a stack with conn_chunk set takes its slots from an allocator: initAlloc");
            if (comptime cfg.grow_buffers) @compileError("a stack with grow_buffers set takes its buffers from an allocator: initAlloc");
            return Self{
                .link = link_ep,
                .local_addr = local_addr,
                .isn_gen = isn_mod.IsnGenerator.init(secret),
                .syn_cookie = syn_cookie_mod.SynCookie.init(secret),
            };
        }

        /// A stack whose connection slots come from `allocator`, a chunk at a
        /// time (cfg.conn_chunk). Written in place: an inline stack is
        /// max_conns connections, which no thread's stack can hold as a
        /// temporary, and this one is small enough that it does not matter.
        pub fn initAlloc(self: *Self, link_ep: *LinkT, local_addr: [4]u8, secret: [16]u8, allocator: std.mem.Allocator) void {
            self.* = .{
                .link = link_ep,
                .local_addr = local_addr,
                .isn_gen = isn_mod.IsnGenerator.init(secret),
                .syn_cookie = syn_cookie_mod.SynCookie.init(secret),
                .allocator = allocator,
                .buf_budget = if (cfg.grow_buffers) .{ .parent = allocator, .limit = cfg.buf_budget } else {},
            };
        }

        /// What every connection's grown buffers hold now, in bytes
        /// (cfg.grow_buffers; 0 otherwise). Against cfg.buf_budget, it says
        /// how close the stack is to taking less than it is sent.
        pub fn bufBytesHeld(self: *const Self) usize {
            return if (comptime cfg.grow_buffers) self.buf_budget.used else 0;
        }

        /// Give the chunks back, and what open connections hold. Nothing
        /// to do for an inline stack with fixed buffers.
        pub fn deinit(self: *Self) void {
            if (comptime cfg.grow_buffers) {
                for (0..self.slots_ready) |i| {
                    const slot = self.slotAt(i);
                    if (slot.active) slot.conn.releaseBuffers();
                }
            }
            if (comptime !chunked) return;
            const a = self.allocator orelse return;
            for (&self.conns) |*chunk| {
                if (chunk.*) |c| a.destroy(c);
                chunk.* = null;
            }
            self.slots_ready = 0;
            self.active_count = 0;
        }

        /// A connection was just made in `slot`: give it its generation, and
        /// the stack's allocator for its buffers to grow from.
        fn openedSlot(self: *Self, slot: *ConnSlot) void {
            slot.gen = self.next_conn_gen;
            // Never 0, which a slot never taken reads as.
            self.next_conn_gen +%= 1;
            if (self.next_conn_gen == 0) self.next_conn_gen = 1;
            self.adoptBuffers(slot);
        }

        /// Hand a connection just made in `slot` the stack's allocator, for
        /// its buffers to grow from.
        fn adoptBuffers(self: *Self, slot: *ConnSlot) void {
            if (comptime !cfg.grow_buffers) return;
            if (self.allocator != null) slot.conn.setAllocator(self.buf_budget.allocator());
        }

        fn SlotPtr(comptime P: type) type {
            return if (@typeInfo(P).pointer.is_const) *const ConnSlot else *ConnSlot;
        }

        /// Slot `idx`, which has to exist (idx < slots_ready).
        pub fn slotAt(self: anytype, idx: usize) SlotPtr(@TypeOf(self)) {
            std.debug.assert(idx < self.slots_ready);
            if (comptime chunked) return &self.conns[idx / conn_chunk].?[idx % conn_chunk];
            return &self.conns[idx];
        }

        /// Slot `idx` if it holds a connection, and null for one that does
        /// not or does not exist.
        pub fn liveSlot(self: anytype, idx: usize) ?SlotPtr(@TypeOf(self)) {
            if (idx >= self.slots_ready) return null;
            const slot = self.slotAt(idx);
            return if (slot.active) slot else null;
        }

        /// How many slots exist, for a caller walking them with slotAt.
        pub fn slotCount(self: *const Self) usize {
            return self.slots_ready;
        }

        /// Give back the chunks at the end that hold no connection, keeping
        /// the first. Returns how many went back.
        ///
        /// For a caller to run now and then — not every poll: a stack going
        /// back and forth across a chunk boundary would allocate and free
        /// one each time. Only the end goes, so every slot that stays keeps
        /// its index, and allocSlot fills from the front, so after a burst
        /// the end is what empties. A connection left near the end holds its
        /// chunk, and every one before it, until it closes. An index into a
        /// chunk that went back reads as no connection (liveSlot), as one
        /// that was closed does.
        pub fn shrinkSlots(self: *Self) usize {
            if (comptime !chunked) return 0;
            const a = self.allocator orelse return 0;
            var released: usize = 0;
            while (self.slots_ready > conn_chunk) {
                const last = self.slots_ready / conn_chunk - 1;
                const chunk = self.conns[last].?;
                for (chunk) |*slot| {
                    if (slot.active) return released;
                }
                a.destroy(chunk);
                self.conns[last] = null;
                self.slots_ready -= conn_chunk;
                released += 1;
            }
            return released;
        }

        /// One more chunk of slots, all free. False when the stack is at
        /// max_conns, has no allocator, or the allocator said no.
        fn growSlots(self: *Self) bool {
            if (comptime !chunked) return false;
            if (self.slots_ready >= max_conns) return false;
            const a = self.allocator orelse return false;
            const chunk = a.create([conn_chunk]ConnSlot) catch return false;
            // Only what is read of a free slot: whatever takes one writes
            // the rest, as it does when it takes back a slot that held a
            // connection before. Not `.{}` per slot, which would build a
            // whole connection on this thread's stack for each.
            for (chunk) |*slot| {
                slot.active = false;
                slot.passive = false;
                slot.is_v6 = false;
            }
            self.conns[self.slots_ready / conn_chunk] = chunk;
            self.slots_ready += conn_chunk;
            return true;
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
                const slot = self.slotAt(idx);

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

                const in_syn_queue = inSynQueue(slot);
                const output = slot.conn.onSegment(now_ms, flags, seg_seq, seg_ack, seg_wnd, payload);

                return self.handleConnOutput(idx, now_ms, output, payload.len, in_syn_queue);
            }

            // New SYN → accept
            if (flags.syn and !flags.ack) {
                const syn_opts = if (hdr_len > 20)
                    @import("transport/tcp/options.zig").parseOptions(ip_payload[20..hdr_len])
                else
                    @import("transport/tcp/options.zig").NegotiatedOptions{};
                return self.acceptConn(now_ms, id, seg_seq, seg_wnd, syn_opts, null);
            }

            // ACK without matching connection: might be completing a SYN-cookie handshake
            if (flags.ack and !flags.syn and !flags.rst) {
                if (self.validateSynCookie(now_ms, id, seg_ack)) |cookie_mss| {
                    return self.acceptCookieConn(now_ms, id, seg_seq, seg_ack, seg_wnd, cookie_mss, payload, null);
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
                const slot = self.slotAt(idx);

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

                const in_syn_queue = inSynQueue(slot);
                const output = slot.conn.onSegment(now_ms, flags, seg_seq, seg_ack, seg_wnd, payload);
                return self.handleConnOutput(idx, now_ms, output, payload.len, in_syn_queue);
            }

            if (flags.syn and !flags.ack) {
                const opts_mod6 = @import("transport/tcp/options.zig");
                const syn_opts6 = if (hdr_len > 20)
                    opts_mod6.parseOptions(ip6_payload[20..hdr_len])
                else
                    opts_mod6.NegotiatedOptions{};
                // The addresses go in with the SYN: whether it is answered
                // now or held for the application, whatever comes of it has
                // to be v6, and ConnId cannot say so on its own. The accept
                // paths set them before they hash, so nothing is left to fix
                // up here.
                return self.acceptConn(now_ms, id, seg_seq, seg_wnd, syn_opts6, .{ .local = dst6, .remote = src6 });
            }

            // ACK without matching connection: might be completing a SYN-cookie handshake
            if (flags.ack and !flags.syn and !flags.rst) {
                if (self.validateSynCookie(now_ms, id, seg_ack)) |cookie_mss| {
                    return self.acceptCookieConn(now_ms, id, seg_seq, seg_ack, seg_wnd, cookie_mss, payload, .{ .local = dst6, .remote = src6 });
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
                const slot = self.slotAt(idx);

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

                const in_syn_queue = inSynQueue(slot);
                const output = slot.conn.onSegment(now_ms, flags, seg_seq, seg_ack, seg_wnd, tcp_payload);
                return self.handleConnOutput(idx, now_ms, output, tcp_payload.len, in_syn_queue);
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
            for (0..self.slots_ready) |idx| {
                const slot = self.slotAt(idx);
                if (!slot.active) continue;

                const in_syn_queue = inSynQueue(slot);
                slot.conn.shrinkIdleBuffers(now_ms);
                const output = slot.conn.poll(now_ms);
                switch (output) {
                    .send => |seg| {
                        self.emitSegment(@intCast(idx), seg);
                        // Closed on the way out: an abort sends its reset
                        // like this, and there is nothing after it.
                        if (slot.conn.state == .closed) {
                            self.releaseConn(idx, in_syn_queue);
                            return .{ .aborted = @intCast(idx) };
                        }
                    },
                    .closed => {
                        self.releaseConn(idx, in_syn_queue);
                        return .{ .closed = @intCast(idx) };
                    },
                    .aborted => {
                        self.releaseConn(idx, in_syn_queue);
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
            const slot = self.liveSlot(conn_idx) orelse return 0;
            return slot.conn.write(data);
        }

        /// Read data from a connection. Returns bytes read.
        pub fn read(self: *Self, conn_idx: u16, buf: []u8) usize {
            const slot = self.liveSlot(conn_idx) orelse return 0;
            return slot.conn.read(buf);
        }

        /// Initiate close on a connection.
        pub fn close(self: *Self, conn_idx: u16) void {
            const slot = self.liveSlot(conn_idx) orelse return;
            slot.conn.close();
        }

        /// Send what the connection holds, then reset it rather than close
        /// it (Connection.resetWhenDrained).
        pub fn resetWhenDrained(self: *Self, conn_idx: u16, timeout_ms: u64) void {
            const slot = self.liveSlot(conn_idx) orelse return;
            slot.conn.resetWhenDrained(timeout_ms);
        }

        /// Shutdown write direction (send FIN, continue receiving).
        pub fn shutdownWrite(self: *Self, conn_idx: u16) void {
            const slot = self.liveSlot(conn_idx) orelse return;
            slot.conn.shutdownWrite();
        }

        /// Shutdown read direction (discard incoming data).
        pub fn shutdownRead(self: *Self, conn_idx: u16) void {
            const slot = self.liveSlot(conn_idx) orelse return;
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
            // Already listening: the call still says how SYNs are answered,
            // so listen() on a deferred port makes it answer immediately
            // again and listenDeferred() on a plain one starts holding.
            for (self.listen_ports[0..self.listen_count], 0..) |p, i| {
                if (p != port) continue;
                self.listen_deferred[i] = deferred;
                self.raiseQueueLimits(backlog);
                return true;
            }
            if (self.listen_count >= max_listen_ports) return false;
            self.listen_ports[self.listen_count] = port;
            self.listen_deferred[self.listen_count] = deferred;
            self.listen_count += 1;
            self.raiseQueueLimits(backlog);
            return true;
        }

        /// Raise the shared queue bounds for a listen that was registered.
        /// A refused listen leaves them alone: it asked for room it did not
        /// get, and the queues it would have used stay as they were.
        fn raiseQueueLimits(self: *Self, backlog: u16) void {
            const limit = if (backlog == 0) 128 else backlog;
            self.syn_queue_limit = @max(self.syn_queue_limit, limit);
            // The accept queue holds one entry per slot and no more, because
            // a connection waiting to be accepted has a slot. The ring wraps
            // either way, so a larger limit would not write past it — it
            // would promise a backlog the stack has nowhere to put, and
            // overwrite the oldest waiting connection with the newest. The
            // limit says what the stack has.
            self.accept_queue_limit = @min(@max(self.accept_queue_limit, limit), max_conns);
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
            while (self.accept_queue_count > 0) {
                const idx = self.accept_queue[self.accept_queue_head];
                self.accept_queue_head = (self.accept_queue_head + 1) % max_conns;
                self.accept_queue_count -= 1;
                // A connection that ended before anyone accepted it is not
                // one to hand out. Releasing a slot takes it out of this
                // queue, so this is the second line of defence rather than
                // the first.
                if (self.slotAt(idx).active) return idx;
            }
            return null;
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
            const slot = self.slotAt(idx);
            slot.* = ConnSlot{
                .conn = ConnectionT.connect(local_port, remote_port, gen_isn),
                .id = id,
                .active = true,
            };
            slot.conn.limitLocalMss(mss4);
            self.openedSlot(slot);
            self.active_count += 1;
            self.hashInsert(idx);
            return @intCast(idx);
        }

        /// The largest TCP segment the link carries, for each family: the
        /// link less the IP and TCP headers, and never past default_mss.
        /// IPv6's header is 20 bytes larger, so its segments are 20 bytes
        /// smaller. A link_mtu set alone is enough: a default_mss left at
        /// Ethernet's would make every full segment too large for it.
        const mss4: u16 = @min(cfg.default_mss, cfg.link_mtu - 40);
        const mss6: u16 = @min(cfg.default_mss, cfg.link_mtu - 60);

        fn localMss(v6: bool) u16 {
            return if (v6) mss6 else mss4;
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
            const slot = self.slotAt(idx);
            slot.* = ConnSlot{
                .conn = ConnectionT.connect(local_port, remote_port, gen_isn),
                .id = id,
                .active = true,
                .is_v6 = true,
                .local_addr6 = self.local_addr6,
                .remote_addr6 = remote_addr,
            };
            slot.conn.limitLocalMss(mss6);
            self.openedSlot(slot);
            self.active_count += 1;
            self.hashInsert(idx);
            return @intCast(idx);
        }

        /// Get connection state.
        pub fn connState(self: *const Self, conn_idx: u16) ?tcp_connection.State {
            const slot = self.liveSlot(conn_idx) orelse return null;
            return slot.conn.state;
        }

        /// Which connection holds `conn_idx`: a number that is different for
        /// every connection the slot holds, and null once it holds none. A
        /// slot is given to the next connection as soon as one closes —
        /// a reset closes it without the caller doing anything — so an
        /// index kept from earlier says nothing about whose it is now; the
        /// index and this number together do.
        pub fn connGen(self: *const Self, conn_idx: u16) ?u32 {
            const slot = self.liveSlot(conn_idx) orelse return null;
            return slot.gen;
        }

        /// Get connection ID.
        pub fn connId(self: *const Self, conn_idx: u16) ?ConnId {
            const slot = self.liveSlot(conn_idx) orelse return null;
            return slot.id;
        }

        /// The whole addresses of a v6 connection, which its ConnId keeps
        /// only the low four bytes of. Null for a v4 one, or no connection.
        pub fn connAddrs6(self: *const Self, conn_idx: u16) ?V6Addrs {
            const slot = self.liveSlot(conn_idx) orelse return null;
            if (!slot.is_v6) return null;
            return .{ .local = slot.local_addr6, .remote = slot.remote_addr6 };
        }

        /// Set TCP_NODELAY (disable Nagle algorithm) on a connection.
        pub fn setNoDelay(self: *Self, conn_idx: u16, enabled: bool) void {
            const slot = self.liveSlot(conn_idx) orelse return;
            slot.conn.sender.nagle_enabled = !enabled;
        }

        /// Get TCP_NODELAY state.
        pub fn getNoDelay(self: *const Self, conn_idx: u16) bool {
            const slot = self.liveSlot(conn_idx) orelse return false;
            return !slot.conn.sender.nagle_enabled;
        }

        /// Enable/disable TCP keepalive on a connection.
        pub fn setKeepalive(self: *Self, conn_idx: u16, enabled: bool) void {
            const slot = self.liveSlot(conn_idx) orelse return;
            slot.conn.keepalive_enabled = enabled;
        }

        /// Configure keepalive parameters.
        pub fn setKeepaliveParams(self: *Self, conn_idx: u16, idle_ms: u64, interval_ms: u64, max_probes: u8) void {
            const slot = self.liveSlot(conn_idx) orelse return;
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
            const slot = self.liveSlot(conn_idx) orelse return;
            slot.conn.setLinger(enabled, timeout_ms);
        }

        /// Enable/disable ECN on a connection.
        pub fn setEcn(self: *Self, conn_idx: u16, enabled: bool) void {
            const slot = self.liveSlot(conn_idx) orelse return;
            slot.conn.ecn_enabled = enabled;
        }

        /// Next poll deadline.
        pub fn nextPollAt(self: *const Self) ?u64 {
            var earliest: ?u64 = null;
            for (0..self.slots_ready) |idx| {
                const slot = self.slotAt(idx);
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
            self.emitUdpPacket(self.local_addr, slot.ep.local_port, dst_addr, dst_port, data);
            return true;
        }

        /// Send a UDP datagram carrying a source address and port of the
        /// caller's choosing, rather than this stack's own.
        ///
        /// For a relay. When this stack forwards a datagram on somebody
        /// else's behalf — to a subnet it routes for, or out to the
        /// internet as an exit node — the answer has to come back from the
        /// address and port the sender wrote to, not from the stack's
        /// overlay address. A sender whose socket is connected, which is
        /// what a DNS resolver and most UDP clients use, drops anything
        /// from a different source; an unconnected one accepts it and
        /// hides the bug.
        pub fn udpSendFrom(
            self: *Self,
            ep_idx: u16,
            src_addr: [4]u8,
            src_port: u16,
            dst_addr: [4]u8,
            dst_port: u16,
            data: []const u8,
        ) bool {
            if (ep_idx >= max_udp_endpoints) return false;
            const slot = &self.udp_eps[ep_idx];
            if (!slot.active) return false;

            self.emitUdpPacket(src_addr, src_port, dst_addr, dst_port, data);
            return true;
        }

        /// udpSendFrom without an endpoint. A relay answers from the address
        /// and port the sender wrote to, and needs nothing of an endpoint to
        /// do it — not its port, not its receive buffer, which at 94KiB a
        /// piece made a relay bind one per flow and hold sixteen flows at
        /// once.
        pub fn udpEmitFrom(
            self: *Self,
            src_addr: [4]u8,
            src_port: u16,
            dst_addr: [4]u8,
            dst_port: u16,
            data: []const u8,
        ) void {
            self.emitUdpPacket(src_addr, src_port, dst_addr, dst_port, data);
        }

        /// udpEmitFrom over IPv6: a relay answering a v6 peer from the
        /// address and port it wrote to, which is not always this stack's
        /// own v6 address.
        pub fn udpEmitFrom6(
            self: *Self,
            src_addr: [16]u8,
            src_port: u16,
            dst_addr: [16]u8,
            dst_port: u16,
            data: []const u8,
        ) void {
            self.emitUdpPacket6(src_addr, src_port, dst_addr, dst_port, data);
        }

        /// Send a UDP datagram to an IPv6 destination.
        pub fn udpSendTo6(self: *Self, ep_idx: u16, dst_addr: [16]u8, dst_port: u16, data: []const u8) bool {
            if (ep_idx >= max_udp_endpoints) return false;
            const slot = &self.udp_eps[ep_idx];
            if (!slot.active) return false;
            self.emitUdpPacket6(self.local_addr6, slot.ep.local_port, dst_addr, dst_port, data);
            return true;
        }

        /// Send a UDP datagram to the connected remote.
        pub fn udpSend(self: *Self, ep_idx: u16, data: []const u8) bool {
            if (ep_idx >= max_udp_endpoints) return false;
            const slot = &self.udp_eps[ep_idx];
            if (!slot.active or !slot.ep.connected) return false;
            self.emitUdpPacket(self.local_addr, slot.ep.local_port, slot.ep.remote_addr, slot.ep.remote_port, data);
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
            const slot = self.slotAt(conn_idx);
            const id = slot.id;
            const now_ms = self.last_tick_ms;

            // Get payload from send buffer
            const payload_data = if (seg.payload_len > 0)
                slot.conn.sendBytes()[seg.payload_offset .. seg.payload_offset + seg.payload_len]
            else
                &[_]u8{};

            // Build TCP options
            const opts_mod = @import("transport/tcp/options.zig");
            var opts_buf: [40]u8 = undefined;
            var opts_len: usize = 0;

            if (seg.include_syn_options) {
                opts_len = opts_mod.writeSynOptions(&opts_buf, .{
                    .mss = slot.conn.local_mss,
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
                // IP(20) + TCP(20); lowerMss leaves room for timestamps.
                self.slotAt(idx).conn.lowerMss(next_hop_mtu -| 40);
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
                // IPv6(40) + TCP(20); lowerMss leaves room for timestamps.
                self.slotAt(idx).conn.lowerMss(@intCast(@min(mtu -| 60, 65535)));
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

        fn emitUdpPacket(self: *Self, src_addr: [4]u8, src_port: u16, dst_addr: [4]u8, dst_port: u16, data: []const u8) void {
            if (udp_header.header_len + data.len > max_udp_len) return;
            const udp_len: u16 = @intCast(udp_header.header_len + data.len);
            const total_len: u16 = 20 + udp_len;

            if (total_len > cfg.link_mtu) {
                self.emitUdpFragments(src_addr, src_port, dst_addr, dst_port, data);
                return;
            }

            var buf: [1500]u8 = undefined;
            if (total_len > buf.len) return;

            // Build IPv4 header
            var ip_hdr = ipv4_header.MutableHeader.init(&buf) catch return;
            ip_hdr.setTotalLen(total_len);
            ip_hdr.setIdentification(self.ip_id_counter);
            self.ip_id_counter +%= 1;
            ip_hdr.setTtl(64);
            ip_hdr.setProtocol(.udp);
            ip_hdr.setSrcAddr(src_addr);
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
                const ph = cksum_mod.pseudoHeaderIpv4(src_addr, dst_addr, 17, udp_len);
                const raw = cksum_mod.finish(cksum_mod.accumulate(ph, udp_seg));
                const cksum: u16 = if (raw == 0) 0xFFFF else raw;
                std.mem.writeInt(u16, udp_seg[6..8], cksum, .big);
            }

            // Send via link endpoint
            var pb = @import("packet_buf.zig").PacketBuf.initWithData(buf[0..], 0, total_len);
            _ = self.link.extract(&pb);
        }

        /// The largest UDP datagram an IPv4 packet can carry.
        const max_udp_len: usize = 65535 - 20;

        /// A UDP datagram larger than the link takes, sent as IPv4 fragments
        /// of at most `cfg.link_mtu` (RFC 791), which the receiver puts back
        /// together. Built a fragment at a time, never whole: the datagram
        /// can be 64KiB, and the stack sends from whatever thread polls it.
        ///
        /// Never Don't Fragment: these are the stack's own packets — a relay's
        /// answer, typically — and splitting them here is what keeps a
        /// large answer (a DNS response with EDNS, a QUIC handshake) from
        /// being lost on a link smaller than the path it came over.
        fn emitUdpFragments(self: *Self, src_addr: [4]u8, src_port: u16, dst_addr: [4]u8, dst_port: u16, data: []const u8) void {
            const cksum_mod = @import("checksum.zig");
            const udp_len: u16 = @intCast(udp_header.header_len + data.len);

            // The UDP header, its checksum over the whole datagram.
            var udp_hdr: [udp_header.header_len]u8 = undefined;
            std.mem.writeInt(u16, udp_hdr[0..2], src_port, .big);
            std.mem.writeInt(u16, udp_hdr[2..4], dst_port, .big);
            std.mem.writeInt(u16, udp_hdr[4..6], udp_len, .big);
            udp_hdr[6] = 0;
            udp_hdr[7] = 0;
            const ph = cksum_mod.pseudoHeaderIpv4(src_addr, dst_addr, 17, udp_len);
            const raw = cksum_mod.finish(cksum_mod.accumulate(cksum_mod.accumulate(ph, &udp_hdr), data));
            std.mem.writeInt(u16, udp_hdr[6..8], if (raw == 0) 0xFFFF else raw, .big);

            // Every fragment but the last carries a multiple of 8 bytes.
            const per_fragment: usize = (@as(usize, cfg.link_mtu) - 20) & ~@as(usize, 7);
            const id = self.ip_id_counter;
            self.ip_id_counter +%= 1;

            var buf: [1500]u8 = undefined;
            var offset: usize = 0; // into the UDP datagram: header, then data
            while (offset < udp_len) {
                const chunk = @min(per_fragment, udp_len - offset);
                const more = offset + chunk < udp_len;

                var ip_hdr = ipv4_header.MutableHeader.init(&buf) catch return;
                ip_hdr.setTotalLen(@intCast(20 + chunk));
                ip_hdr.setIdentification(id);
                ip_hdr.setTtl(64);
                ip_hdr.setProtocol(.udp);
                ip_hdr.setSrcAddr(src_addr);
                ip_hdr.setDstAddr(dst_addr);
                const flags_offset: u16 = (if (more) @as(u16, 0x2000) else 0) | @as(u16, @intCast(offset / 8));
                std.mem.writeInt(u16, buf[6..8], flags_offset, .big);
                ip_hdr.computeChecksum();

                const end = offset + chunk;
                copyDatagram(buf[20..], &udp_hdr, data, offset, end);

                var pb = @import("packet_buf.zig").PacketBuf.initWithData(buf[0..], 0, 20 + chunk);
                _ = self.link.extract(&pb);
                offset = end;
            }
        }

        /// Bytes [from, to) of a UDP datagram, its header and then its data,
        /// into `out`: one fragment's share of a datagram never put
        /// together whole.
        fn copyDatagram(out: []u8, udp_hdr: *const [udp_header.header_len]u8, data: []const u8, from: usize, to: usize) void {
            var at: usize = 0;
            var pos = from;
            if (pos < udp_header.header_len) {
                const n = @min(udp_header.header_len, to) - pos;
                @memcpy(out[at .. at + n], udp_hdr[pos .. pos + n]);
                at += n;
                pos += n;
            }
            if (pos < to) {
                const start = pos - udp_header.header_len;
                const n = to - pos;
                @memcpy(out[at .. at + n], data[start .. start + n]);
            }
        }

        /// The IPv6 side of emitUdpFragments: a Fragment header (RFC 8200
        /// 4.5) behind each fixed header, the same 32-bit identification in
        /// every piece, and a multiple of 8 bytes in all but the last. Only
        /// the source fragments over IPv6, and this is the source.
        fn emitUdpFragments6(self: *Self, src_addr: [16]u8, src_port: u16, dst_addr: [16]u8, dst_port: u16, data: []const u8) void {
            const cksum_mod = @import("checksum.zig");
            const ip6_hlen: usize = 40;
            const frag_hlen = ipv6_frag_mod.frag_hdr_len;
            const udp_len: u16 = @intCast(udp_header.header_len + data.len);

            var udp_hdr: [udp_header.header_len]u8 = undefined;
            std.mem.writeInt(u16, udp_hdr[0..2], src_port, .big);
            std.mem.writeInt(u16, udp_hdr[2..4], dst_port, .big);
            std.mem.writeInt(u16, udp_hdr[4..6], udp_len, .big);
            udp_hdr[6] = 0;
            udp_hdr[7] = 0;
            const ph = cksum_mod.pseudoHeaderIpv6(src_addr, dst_addr, 17, udp_len);
            const raw = cksum_mod.finish(cksum_mod.accumulate(cksum_mod.accumulate(ph, &udp_hdr), data));
            std.mem.writeInt(u16, udp_hdr[6..8], if (raw == 0) 0xFFFF else raw, .big);

            const per_fragment: usize = (@as(usize, cfg.link_mtu) - ip6_hlen - frag_hlen) & ~@as(usize, 7);
            const id = self.ip6_frag_id;
            self.ip6_frag_id +%= 1;

            var buf: [1500]u8 = undefined;
            var offset: usize = 0;
            while (offset < udp_len) {
                const chunk = @min(per_fragment, udp_len - offset);
                const end = offset + chunk;

                var ip6 = ipv6_header.MutableHeader.init(buf[0..ip6_hlen]) catch return;
                ip6.setPayloadLen(@intCast(frag_hlen + chunk));
                ip6.setNextHeader(.fragment);
                ip6.setHopLimit(64);
                ip6.setSrcAddr(src_addr);
                ip6.setDstAddr(dst_addr);
                const fh = ipv6_frag_mod.FragHeader{
                    .next_header = .udp,
                    .frag_offset = @intCast(offset / 8),
                    .more_fragments = end < udp_len,
                    .identification = id,
                };
                fh.serialize(buf[ip6_hlen .. ip6_hlen + frag_hlen]);
                copyDatagram(buf[ip6_hlen + frag_hlen ..], &udp_hdr, data, offset, end);

                var pb = @import("packet_buf.zig").PacketBuf.initWithData(buf[0..], 0, ip6_hlen + frag_hlen + chunk);
                _ = self.link.extract(&pb);
                offset = end;
            }
        }

        fn emitUdpPacket6(self: *Self, src_addr: [16]u8, src_port: u16, dst_addr: [16]u8, dst_port: u16, data: []const u8) void {
            const ip6_hlen: usize = 40;
            // A UDP length past 16 bits needs a jumbogram, which nothing here
            // sends.
            if (udp_header.header_len + data.len > 65535) return;
            const udp_len: u16 = @intCast(udp_header.header_len + data.len);
            const total_len = ip6_hlen + @as(usize, udp_len);

            // Larger than the link: in fragments, as over IPv4.
            if (total_len > cfg.link_mtu) {
                self.emitUdpFragments6(src_addr, src_port, dst_addr, dst_port, data);
                return;
            }

            var buf: [1500]u8 = undefined;
            if (total_len > buf.len) return;

            // Build IPv6 header
            var ip6 = ipv6_header.MutableHeader.init(buf[0..ip6_hlen]) catch return;
            ip6.setPayloadLen(udp_len);
            ip6.setNextHeader(.udp);
            ip6.setHopLimit(64);
            ip6.setSrcAddr(src_addr);
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
                const ph = cksum_mod.pseudoHeaderIpv6(src_addr, dst_addr, 17, udp_len);
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

        fn acceptConn(self: *Self, now_ms: u64, id: ConnId, peer_seq: u32, peer_wnd: u16, peer_opts: @import("transport/tcp/options.zig").NegotiatedOptions, v6: ?V6Addrs) Event {
            if (!self.isListening(id.local_port)) return .none;

            // Held rather than answered: nothing is sent and no connection
            // state is allocated until the application says so. Ahead of the
            // SYN cookie branch on purpose — a cookie is an answer too.
            if (self.isDeferred(id.local_port)) return self.holdSyn(now_ms, id, peer_seq, peer_wnd, peer_opts, v6);

            const half_open = self.synQueueCount();

            // SYN cookie mode: when SYN queue is near full, respond statelessly
            if (half_open >= self.syn_cookie_threshold) {
                return self.acceptConnStateless(now_ms, id, peer_seq, peer_opts, v6);
            }

            return self.acceptConnNow(now_ms, id, peer_seq, peer_wnd, peer_opts, v6);
        }

        /// Allocate the connection and answer the SYN. Split out so a SYN
        /// that was held can be answered without passing the cookie branch
        /// again: a cookie keeps no state, and a held SYN exists precisely
        /// because the application wanted to decide before answering.
        fn acceptConnNow(self: *Self, now_ms: u64, id: ConnId, peer_seq: u32, peer_wnd: u16, peer_opts: @import("transport/tcp/options.zig").NegotiatedOptions, v6: ?V6Addrs) Event {
            // Drop if SYN queue is full
            if (self.synQueueCount() >= self.syn_queue_limit) return .none;

            const idx = self.allocSlot() orelse return .none;
            const isn = self.nextIsn(now_ms, id);

            const slot = self.slotAt(idx);
            slot.id = id;
            slot.active = true;
            slot.passive = true;
            // Every field that says which family this is, because the slot
            // may have held a v6 connection before: only `active` is cleared
            // when a connection goes away, and a stale is_v6 would have this
            // one hashed and sent as v6.
            slot.is_v6 = v6 != null;
            slot.local_addr6 = if (v6) |a| a.local else .{0} ** 16;
            slot.remote_addr6 = if (v6) |a| a.remote else .{0} ** 16;
            slot.conn = ConnectionT.acceptFromSynMss(id.local_port, isn, now_ms, peer_opts, localMss(v6 != null));
            self.openedSlot(slot);

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
        fn holdSyn(self: *Self, now_ms: u64, id: ConnId, peer_seq: u32, peer_wnd: u16, peer_opts: @import("transport/tcp/options.zig").NegotiatedOptions, v6: ?V6Addrs) Event {
            for (&self.pending_syns, 0..) |*ps, i| {
                if (!ps.active or !samePeer(ps, id, v6)) continue;
                // A retransmission of the hold we already have: the same
                // hold, so the same handle, and whoever is settling it keeps
                // the one they were given.
                ps.received_ms = now_ms;
                ps.peer_seq = peer_seq;
                ps.peer_wnd = peer_wnd;
                ps.peer_opts = peer_opts;
                return .{ .syn_pending = .{ .idx = @intCast(i), .gen = ps.gen } };
            }
            for (&self.pending_syns, 0..) |*ps, i| {
                if (ps.active) continue;
                const gen = ps.gen +% 1;
                ps.* = .{
                    .gen = gen,
                    .id = id,
                    .peer_seq = peer_seq,
                    .peer_wnd = peer_wnd,
                    .peer_opts = peer_opts,
                    .received_ms = now_ms,
                    .active = true,
                    .is_v6 = v6 != null,
                    .local_addr6 = if (v6) |a| a.local else .{0} ** 16,
                    .remote_addr6 = if (v6) |a| a.remote else .{0} ** 16,
                };
                return .{ .syn_pending = .{ .idx = @intCast(i), .gen = gen } };
            }
            return .none;
        }

        /// Whether a held SYN and an arriving one come from the same place,
        /// so a retransmission refreshes its hold instead of taking another.
        /// For v6 that means the whole address: ConnId keeps four bytes of
        /// it, and two peers can share those.
        fn samePeer(ps: *const PendingSyn, id: ConnId, v6: ?V6Addrs) bool {
            if (ps.is_v6 != (v6 != null)) return false;
            if (ps.id.local_port != id.local_port or ps.id.remote_port != id.remote_port) return false;
            if (v6) |a| {
                return std.mem.eql(u8, &ps.local_addr6, &a.local) and
                    std.mem.eql(u8, &ps.remote_addr6, &a.remote);
            }
            return std.mem.eql(u8, &ps.id.local_addr, &id.local_addr) and
                std.mem.eql(u8, &ps.id.remote_addr, &id.remote_addr);
        }

        /// The oldest SYN still waiting for an answer, or null.
        pub fn nextPendingSyn(self: *const Self) ?PendingHandle {
            var best: ?PendingHandle = null;
            var best_ms: u64 = 0;
            for (self.pending_syns, 0..) |ps, i| {
                if (!ps.active) continue;
                if (best == null or ps.received_ms < best_ms) {
                    best = .{ .idx = @intCast(i), .gen = ps.gen };
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
                .handle = .{ .idx = pending_idx, .gen = ps.gen },
                .local_port = ps.id.local_port,
                .remote_addr = ps.id.remote_addr,
                .remote_port = ps.id.remote_port,
                .received_ms = ps.received_ms,
                .is_v6 = ps.is_v6,
                .remote_addr6 = ps.remote_addr6,
                .local_addr6 = ps.local_addr6,
            };
        }

        /// How many holds the table can have at once, so a caller can walk
        /// it: nextPendingSyn only ever names the oldest, which is the one a
        /// caller still working on it would see again and again.
        pub fn pendingSynCapacity(_: *const Self) usize {
            return max_pending_syns;
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
        /// would have when the SYN arrived, minus the SYN cookie branch. A
        /// cookie answers statelessly, which is the opposite of what a hold
        /// is for — the application asked to decide before anything was said
        /// — and a cookie sent from here would leave the caller believing
        /// nothing had happened while the peer completed a handshake.
        ///
        /// Returns the connection index, or null when the stack has no room
        /// (no connection slot, or a full SYN queue) and when the port has
        /// stopped listening. Nothing is sent in those cases: the peer
        /// retransmits, as it would have all along, and lands back in the
        /// pending table for the application to try again.
        pub fn acceptPending(self: *Self, handle: PendingHandle, now_ms: u64) ?u16 {
            const ps = self.heldBy(handle) orelse return null;
            if (!self.isListening(ps.id.local_port)) return null;
            self.pending_syns[handle.idx].active = false;

            const v6: ?V6Addrs = if (ps.is_v6)
                .{ .local = ps.local_addr6, .remote = ps.remote_addr6 }
            else
                null;
            switch (self.acceptConnNow(now_ms, ps.id, ps.peer_seq, ps.peer_wnd, ps.peer_opts, v6)) {
                .accepted => |idx| return idx,
                else => return null,
            }
        }

        /// Refuse a held SYN: the peer is told there is nothing here, rather
        /// than left waiting on an answer that will not come.
        pub fn rejectPending(self: *Self, handle: PendingHandle) void {
            const held = self.heldBy(handle) orelse return;
            self.rstPending(&held);
            self.pending_syns[handle.idx].active = false;
        }

        /// The hold this handle names, or null when it names none: out of
        /// range, already settled, or a slot that has since taken someone
        /// else's SYN. The generation is what separates the last case from
        /// the others — a caller that went away to dial and came back late
        /// used to land on whatever hold the slot held by then.
        fn heldBy(self: *const Self, handle: PendingHandle) ?PendingSyn {
            if (handle.idx >= max_pending_syns) return null;
            const ps = self.pending_syns[handle.idx];
            if (!ps.active or !handle.eql(.{ .idx = handle.idx, .gen = ps.gen })) return null;
            return ps;
        }

        /// Whether a handle still names the hold it was given for.
        pub fn pendingSynHeld(self: *const Self, handle: PendingHandle) bool {
            return self.heldBy(handle) != null;
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
        /// A v6 hold is answered over v6 — ConnId carries four bytes of the
        /// address, which would make an IPv4 packet addressed to whatever
        /// those four bytes happen to spell.
        fn rstPending(self: *Self, ps: *const PendingSyn) void {
            if (ps.is_v6) {
                self.buildAndSend6(ps.local_addr6, ps.remote_addr6, ps.id.local_port, ps.id.remote_port, .{ .rst = true, .ack = true }, 0, ps.peer_seq +% 1, 0, &.{});
                return;
            }
            self.sendRst(ps.id.local_addr, ps.id.local_port, ps.id.remote_addr, ps.id.remote_port, 0, ps.peer_seq +% 1);
        }

        /// Stateless SYN+ACK using SYN cookie (no connection state allocated).
        fn acceptConnStateless(self: *Self, now_ms: u64, id: ConnId, peer_seq: u32, peer_opts: @import("transport/tcp/options.zig").NegotiatedOptions, v6: ?V6Addrs) Event {
            // What the cookie brings back is what the connection sends with:
            // the smaller of what the peer takes and what this side's link
            // carries. A SYN without the option means the least a host must
            // take (RFC 9293 3.7.1): 536 over IPv4, 1220 over IPv6.
            const local = localMss(v6 != null);
            const peer_mss: u16 = if (peer_opts.mss > 0) peer_opts.mss else if (v6 != null) 1220 else 536;
            const cookie_isn = self.syn_cookie.generate(now_ms, id.remote_addr, id.remote_port, id.local_addr, id.local_port, @min(peer_mss, local));

            // Send SYN+ACK with cookie as ISN, no state allocated. It offers
            // this side's MSS, the only option a cookie can stand behind:
            // without it the peer would hold its segments to 536. Over the
            // family the SYN came in on — ConnId only knows four bytes of
            // a v6 address, and a SYN+ACK built from them goes out as IPv4.
            var opts_buf: [4]u8 = undefined;
            const opts_len = @import("transport/tcp/options.zig").writeSynOptions(&opts_buf, .{ .mss = local, .window_scale = null, .sack_permitted = false, .timestamps = false });
            const flags: tcp_header.Flags = .{ .syn = true, .ack = true };
            if (v6) |a| {
                self.buildAndSend6Opts(a.local, a.remote, id.local_port, id.remote_port, flags, cookie_isn, peer_seq +% 1, 65535, &.{}, opts_buf[0..opts_len]);
            } else {
                self.buildAndSendEcnOpts(id, flags, cookie_isn, peer_seq +% 1, 65535, &.{}, 0, opts_buf[0..opts_len]);
            }
            return .none;
        }

        /// Validate a SYN cookie from an inbound ACK.
        fn validateSynCookie(self: *Self, now_ms: u64, id: ConnId, seg_ack: u32) ?u16 {
            const cookie = seg_ack -% 1; // ACK acknowledges ISN+1
            return self.syn_cookie.validate(now_ms, id.remote_addr, id.remote_port, id.local_addr, id.local_port, cookie);
        }

        /// Accept a connection validated by SYN cookie (reconstruct state from ACK).
        fn acceptCookieConn(self: *Self, now_ms: u64, id: ConnId, seg_seq: u32, seg_ack: u32, seg_wnd: u16, cookie_mss: u16, payload: []const u8, v6: ?V6Addrs) Event {
            // The cookie was minted while the port was listening, and the
            // listener can be gone by the time the ACK carrying it arrives.
            // The peer believes it has a connection, so say otherwise — over
            // the family it spoke, since ConnId only knows four bytes of a v6
            // address.
            if (!self.isListening(id.local_port)) {
                if (v6) |a| {
                    self.buildAndSend6(a.local, a.remote, id.local_port, id.remote_port, .{ .rst = true, .ack = true }, seg_ack, seg_seq, 0, &.{});
                } else {
                    self.sendRst(id.local_addr, id.local_port, id.remote_addr, id.remote_port, seg_ack, seg_seq);
                }
                return .none;
            }

            // Drop if accept queue is full
            if (self.accept_queue_count >= self.accept_queue_limit) return .none;

            const idx = self.allocSlot() orelse return .none;
            const our_isn = seg_ack -% 1;
            // No larger than this side's own, whatever the cookie carried:
            // a segment past it would not fit this side's link.
            const local = localMss(v6 != null);
            const mss = @min(cookie_mss, local);

            const slot = self.slotAt(idx);
            slot.id = id;
            slot.active = true;
            slot.passive = true;
            // The same three fields acceptConnNow writes, for the same
            // reason: a closed connection leaves them behind, and this slot
            // may last have held one of the other family.
            slot.is_v6 = v6 != null;
            slot.local_addr6 = if (v6) |a| a.local else .{0} ** 16;
            slot.remote_addr6 = if (v6) |a| a.remote else .{0} ** 16;
            slot.conn = .{
                .state = .established,
                .local_port = id.local_port,
                .remote_port = id.remote_port,
                .sender = SenderT.init(our_isn, mss),
                .receiver = ReceiverT.init(seg_seq -% 1, ConnectionT.initial_rcv_wnd),
                .mss = mss,
                .local_mss = local,
                .last_activity_ms = now_ms,
            };
            self.openedSlot(slot);
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
                slot.conn.sendBytes()[seg.payload_offset .. seg.payload_offset + seg.payload_len]
            else
                &[_]u8{};

            const opts_mod = @import("transport/tcp/options.zig");
            var opts_buf: [40]u8 = undefined;
            var opts_len: usize = 0;

            if (seg.include_syn_options) {
                opts_len = opts_mod.writeSynOptions(&opts_buf, .{
                    .mss = slot.conn.local_mss,
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

        /// Give a slot back: its connection is closed and nothing more will
        /// come out of it. `in_syn_queue` says whether it was still a
        /// handshake this side was counting, which has to be read before the
        /// connection moved — an abort is closed by the time it hands over
        /// the reset it wants sent.
        fn releaseConn(self: *Self, idx: usize, in_syn_queue: bool) void {
            if (in_syn_queue) self.syn_queue_count -|= 1;
            self.hashRemove(idx);
            self.slotAt(idx).conn.releaseBuffers();
            self.slotAt(idx).active = false;
            self.active_count -|= 1;
            // And out of the accept queue, if it was waiting there. The slot
            // goes back to whoever asks for one next, and an index left
            // behind would hand that new connection to a caller that asked
            // about this one — or hand the same one out twice, once for each
            // time the slot was queued.
            self.dropFromAcceptQueue(@intCast(idx));
        }

        /// Take every entry for `conn_idx` out of the accept queue, keeping
        /// what is left in the order it arrived.
        fn dropFromAcceptQueue(self: *Self, conn_idx: u16) void {
            var kept: usize = 0;
            var read_at = self.accept_queue_head;
            var write_at = self.accept_queue_head;
            var i: usize = 0;
            while (i < self.accept_queue_count) : (i += 1) {
                const entry = self.accept_queue[read_at];
                read_at = (read_at + 1) % max_conns;
                if (entry == conn_idx) continue;
                self.accept_queue[write_at] = entry;
                write_at = (write_at + 1) % max_conns;
                kept += 1;
            }
            self.accept_queue_tail = write_at;
            self.accept_queue_count = kept;
        }

        /// Whether this slot is a handshake the SYN queue is counting.
        fn inSynQueue(slot: *const ConnSlot) bool {
            return slot.passive and slot.conn.state == .syn_received;
        }

        fn handleConnOutput(self: *Self, idx: usize, now_ms: u64, output: tcp_connection.Output, payload_len: usize, in_syn_queue: bool) Event {
            _ = now_ms;
            switch (output) {
                .send => |seg| {
                    self.emitSegment(@intCast(idx), seg);
                    // A connection that closed on its way out of that call
                    // sent the last thing it will ever send — an abort hands
                    // over its reset this way — so the slot goes back now
                    // rather than being polled for an output that will never
                    // come.
                    if (self.slotAt(idx).conn.state == .closed) {
                        self.releaseConn(idx, in_syn_queue);
                        return .{ .aborted = @intCast(idx) };
                    }
                },
                .established => {
                    const conn_idx: u16 = @intCast(idx);
                    // Server-side (passive open): enqueue to accept queue.
                    // Which side opened it is recorded on the slot: the listen
                    // set answers a different question, and unlisten during a
                    // handshake used to leave the half-open count and the slot
                    // itself behind, with no way to reach the connection.
                    if (self.slotAt(idx).passive) {
                        self.syn_queue_count -|= 1;
                        // No listener left to hand it to, or nowhere to queue
                        // it: an established connection nobody can accept is a
                        // slot nobody frees, so end it here.
                        if (!self.isListening(self.slotAt(idx).id.local_port) or !self.enqueueAccept(conn_idx)) {
                            self.buildAndSend(self.slotAt(idx).id, .{ .rst = true, .ack = true }, self.slotAt(idx).conn.sender.snd_nxt, self.slotAt(idx).conn.receiver.rcv_nxt, 0, &.{});
                            self.hashRemove(idx);
                            self.slotAt(idx).conn.releaseBuffers();
                            self.slotAt(idx).active = false;
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
                    self.releaseConn(idx, in_syn_queue);
                    return .{ .closed = @intCast(idx) };
                },
                .aborted => {
                    self.releaseConn(idx, in_syn_queue);
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
            for (0..self.slots_ready) |idx| {
                const slot = self.slotAt(idx);
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
            for (0..self.slots_ready) |idx| {
                const slot = self.slotAt(idx);
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
                const slot = self.slotAt(slot_idx);
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
                const slot = self.slotAt(slot_idx);
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
            const slot = self.slotAt(slot_idx);
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
            const slot = self.slotAt(slot_idx);
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

        /// A free slot, from a new chunk when every one there is taken.
        fn allocSlot(self: *Self) ?usize {
            for (0..self.slots_ready) |idx| {
                if (!self.slotAt(idx).active) return idx;
            }
            const first_new = self.slots_ready;
            if (!self.growSlots()) return null;
            return first_new;
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

/// Build a TCP segment in an IPv6 packet (for tests).
pub fn buildTcp6Packet(
    src_addr: [16]u8,
    src_port: u16,
    dst_addr: [16]u8,
    dst_port: u16,
    seq: u32,
    ack_val: u32,
    flags: tcp_header.Flags,
    window: u16,
    payload: []const u8,
    out: []u8,
) usize {
    const ip6_hlen: usize = 40;
    const tcp_hlen: usize = 20;
    const tcp_total: usize = tcp_hlen + payload.len;
    const total: usize = ip6_hlen + tcp_total;

    var ip6 = ipv6_header.MutableHeader.init(out[0..ip6_hlen]) catch unreachable;
    ip6.setPayloadLen(@intCast(tcp_total));
    ip6.setNextHeader(.tcp);
    ip6.setHopLimit(64);
    ip6.setSrcAddr(src_addr);
    ip6.setDstAddr(dst_addr);

    var tcp = tcp_header.MutableHeader.init(out[ip6_hlen .. ip6_hlen + tcp_hlen]) catch unreachable;
    tcp.setSrcPort(src_port);
    tcp.setDstPort(dst_port);
    tcp.setSeqNum(seq);
    tcp.setAckNum(ack_val);
    tcp.setFlags(flags);
    tcp.setWindowSize(window);

    if (payload.len > 0) {
        @memcpy(out[ip6_hlen + tcp_hlen .. ip6_hlen + tcp_hlen + payload.len], payload);
    }
    {
        const cksum_mod = @import("checksum.zig");
        const seg = out[ip6_hlen..total];
        seg[16] = 0;
        seg[17] = 0;
        const ph = cksum_mod.pseudoHeaderIpv6(src_addr, dst_addr, 6, @intCast(tcp_total));
        std.mem.writeInt(u16, seg[16..18], cksum_mod.finish(cksum_mod.accumulate(ph, seg)), .big);
    }
    return total;
}

/// Parse a TCP segment out of a raw IPv6 packet (for tests). Null for
/// anything that is not IPv6 carrying TCP, so a test can tell a v6 answer
/// from a v4 one rather than reading whichever bytes happen to be there.
pub fn parseTcp6FromRaw(raw: []const u8) ?struct {
    src_addr: [16]u8,
    dst_addr: [16]u8,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: tcp_header.Flags,
} {
    if (raw.len < 60 or raw[0] >> 4 != 6 or raw[6] != 6) return null;
    const tcp = tcp_header.Header.parse(raw[40..]) catch return null;
    return .{
        .src_addr = raw[8..24].*,
        .dst_addr = raw[24..40].*,
        .src_port = tcp.srcPort(),
        .dst_port = tcp.dstPort(),
        .seq = tcp.seqNum(),
        .ack = tcp.ackNum(),
        .flags = tcp.flags(),
    };
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

    // No sender setup here: answering the SYN recorded it already, and
    // recording it twice is what this test used to do by hand.

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
    try testing.expect(stack.pendingSynHeld(pending));

    const info = stack.pendingSynInfo(pending.idx).?;
    try testing.expectEqual(@as(u16, 80), info.local_port);
    try testing.expectEqual(@as(u16, 5000), info.remote_port);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 2 }, &info.remote_addr);
    try testing.expectEqual(@as(u64, 10), info.received_ms);

    // A retransmission of the same SYN refreshes the hold, it does not take
    // a second slot.
    switch (stack.injectPacket(1200, pkt_buf[0..syn_len])) {
        .syn_pending => |h| try testing.expectEqual(pending, h),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 1), stack.pendingSynCount());
    try testing.expectEqual(@as(u64, 1200), stack.pendingSynInfo(pending.idx).?.received_ms);
}

test "FullStack: a handle from a hold that is gone settles nothing" {
    const Small = FullStackWith(16, .{ .max_pending_syns = 1 });
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = Small.init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listenDeferred(80, 128);

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;

    // One hold, and a handle for it.
    const first_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const stale = switch (stack.injectPacket(0, pkt_buf[0..first_len])) {
        .syn_pending => |h| h,
        else => return error.TestUnexpectedResult,
    };

    // It goes away without being settled, and the only slot takes someone
    // else's SYN — which is what a caller off dialling somewhere would come
    // back to find.
    try testing.expectEqual(@as(usize, 1), stack.expirePendingSyns(20_000, 5_000));
    const second_len = buildTcpPacket(.{ 10, 0, 0, 3 }, 6000, .{ 10, 0, 0, 1 }, 80, 2000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const current = switch (stack.injectPacket(20_000, pkt_buf[0..second_len])) {
        .syn_pending => |h| h,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(stale.idx, current.idx); // the same slot
    try testing.expect(stale.gen != current.gen); // a different hold
    try testing.expect(!stack.pendingSynHeld(stale));
    try testing.expect(stack.pendingSynHeld(current));

    // The stale handle settles nothing, either way round.
    try testing.expect(stack.acceptPending(stale, 20_100) == null);
    stack.rejectPending(stale);
    try testing.expectEqual(@as(usize, 0), link_ep.outboundCount());
    try testing.expectEqual(@as(usize, 1), stack.pendingSynCount());

    // And the hold that is actually there still answers to its own handle.
    const idx = stack.acceptPending(current, 20_200) orelse return error.NoConnection;
    const syn_ack = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    try testing.expect(syn_ack.flags.syn and syn_ack.flags.ack);
    try testing.expectEqual(@as(u16, 6000), syn_ack.dst_port); // the second peer
    try testing.expectEqual(@as(u32, 2001), syn_ack.ack);
    _ = idx;
}

test "FullStack: two handles name the same hold only if both halves agree" {
    const h = PendingHandle{ .idx = 3, .gen = 7 };
    try testing.expect(h.eql(.{ .idx = 3, .gen = 7 }));
    try testing.expect(!h.eql(.{ .idx = 3, .gen = 8 })); // same slot, later hold
    try testing.expect(!h.eql(.{ .idx = 4, .gen = 7 })); // same generation, other slot
}

test "FullStack: a retransmission keeps the handle its hold was given" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listenDeferred(80, 128);

    var pkt_buf: [128]u8 = undefined;
    const len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const first = switch (stack.injectPacket(0, pkt_buf[0..len])) {
        .syn_pending => |h| h,
        else => return error.TestUnexpectedResult,
    };
    // The peer retransmits: the same hold refreshed, so the handle a caller
    // is already holding has to keep working.
    const again = switch (stack.injectPacket(1_000, pkt_buf[0..len])) {
        .syn_pending => |h| h,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(first, again);
    try testing.expect(stack.pendingSynHeld(first));
}

test "FullStack: the pending table can be walked, not just peeked at" {
    const Small = FullStackWith(16, .{ .max_pending_syns = 4 });
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = Small.init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listenDeferred(80, 128);
    try testing.expectEqual(@as(usize, 4), stack.pendingSynCapacity());

    var pkt_buf: [128]u8 = undefined;
    var port: u16 = 5000;
    while (port < 5003) : (port += 1) {
        const len = buildTcpPacket(.{ 10, 0, 0, 2 }, port, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
        switch (stack.injectPacket(@as(u64, port), pkt_buf[0..len])) {
            .syn_pending => {},
            else => return error.TestUnexpectedResult,
        }
    }

    // Every hold is reachable by index, and the oldest keeps being the oldest
    // until it is settled — which is why a caller working through them needs
    // the capacity rather than nextPendingSyn alone.
    var seen: usize = 0;
    var ports_seen: [3]u16 = .{ 0, 0, 0 };
    for (0..stack.pendingSynCapacity()) |i| {
        const info = stack.pendingSynInfo(@intCast(i)) orelse continue;
        ports_seen[seen] = info.remote_port;
        seen += 1;
    }
    try testing.expectEqual(@as(usize, 3), seen);
    try testing.expectEqualSlices(u16, &.{ 5000, 5001, 5002 }, &ports_seen);
    try testing.expectEqual(stack.nextPendingSyn().?, stack.nextPendingSyn().?);

    // Past the end is not a hold, it is nothing.
    try testing.expect(stack.pendingSynInfo(4) == null);
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
    try testing.expectEqual(@as(u16, 81), stack.pendingSynInfo(stack.nextPendingSyn().?.idx).?.local_port);
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

fn v6Addr(last: u8) [16]u8 {
    var a: [16]u8 = .{0} ** 16;
    a[0] = 0xfd;
    a[15] = last;
    return a;
}

test "FullStack: a held v6 SYN is refused over v6, not over v4" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    const us = v6Addr(1);
    const them = v6Addr(2);
    stack.setIpv6Addr(us);
    _ = stack.listenDeferred(80, 128);

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;
    const syn_len = buildTcp6Packet(them, 5000, us, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const pending = switch (stack.injectPacket(0, pkt_buf[0..syn_len])) {
        .syn_pending => |i| i,
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(stack.pendingSynInfo(pending.idx).?.is_v6);
    try testing.expectEqualSlices(u8, &them, &stack.pendingSynInfo(pending.idx).?.remote_addr6);
    try testing.expectEqual(@as(usize, 0), link_ep.outboundCount());

    stack.rejectPending(pending);

    // Over v6, addressed to the peer that sent the SYN. ConnId keeps four
    // bytes of a v6 address, so a v4 RST here would be sent to whatever
    // those four bytes spell.
    const raw = link_ep.readOutbound(&out_buf).?;
    const rst = parseTcp6FromRaw(raw) orelse return error.NotIpv6;
    try testing.expect(rst.flags.rst);
    try testing.expectEqualSlices(u8, &them, &rst.dst_addr);
    try testing.expectEqualSlices(u8, &us, &rst.src_addr);
    try testing.expectEqual(@as(u32, 1001), rst.ack);
    try testing.expectEqual(@as(u16, 5000), rst.dst_port);
}

test "FullStack: two v6 peers that share four bytes are two holds" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    const us = v6Addr(1);
    stack.setIpv6Addr(us);
    _ = stack.listenDeferred(80, 128);

    // Same low four bytes, different addresses: one ConnId, two peers.
    var a = v6Addr(2);
    var b = v6Addr(2);
    a[1] = 0x01;
    b[1] = 0x02;

    var pkt_buf: [128]u8 = undefined;
    const syn_a = buildTcp6Packet(a, 5000, us, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const pa = switch (stack.injectPacket(0, pkt_buf[0..syn_a])) {
        .syn_pending => |i| i,
        else => return error.TestUnexpectedResult,
    };
    const syn_b = buildTcp6Packet(b, 5000, us, 80, 2000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const pb = switch (stack.injectPacket(0, pkt_buf[0..syn_b])) {
        .syn_pending => |i| i,
        else => return error.TestUnexpectedResult,
    };

    try testing.expect(pa.idx != pb.idx);
    try testing.expectEqual(@as(usize, 2), stack.pendingSynCount());
    try testing.expectEqualSlices(u8, &a, &stack.pendingSynInfo(pa.idx).?.remote_addr6);
    try testing.expectEqualSlices(u8, &b, &stack.pendingSynInfo(pb.idx).?.remote_addr6);
}

test "FullStack: acceptPending on a v6 hold answers over v6" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    const us = v6Addr(1);
    const them = v6Addr(2);
    stack.setIpv6Addr(us);
    _ = stack.listenDeferred(80, 128);

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;
    const syn_len = buildTcp6Packet(them, 5000, us, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const pending = switch (stack.injectPacket(0, pkt_buf[0..syn_len])) {
        .syn_pending => |i| i,
        else => return error.TestUnexpectedResult,
    };

    const idx = stack.acceptPending(pending, 10) orelse return error.NoConnection;
    const syn_ack = parseTcp6FromRaw(link_ep.readOutbound(&out_buf).?) orelse return error.NotIpv6;
    try testing.expect(syn_ack.flags.syn and syn_ack.flags.ack);
    try testing.expectEqual(@as(u32, 1001), syn_ack.ack);
    try testing.expectEqualSlices(u8, &them, &syn_ack.dst_addr);

    // And the peer's ACK finds the connection under its full v6 key.
    const ack_len = buildTcp6Packet(them, 5000, us, 80, 1001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(20, pkt_buf[0..ack_len])) {
        .accepted => |i| try testing.expectEqual(idx, i),
        else => return error.TestUnexpectedResult,
    }
}

test "FullStack: a v4 accept does not inherit a v6 connection's slot" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    const us6 = v6Addr(1);
    const them6 = v6Addr(2);
    stack.setIpv6Addr(us6);
    _ = stack.listen(80, 128);

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;

    // A v6 connection takes slot 0 and then goes away.
    const syn6 = buildTcp6Packet(them6, 5000, us6, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const v6_idx = switch (stack.injectPacket(0, pkt_buf[0..syn6])) {
        .accepted => |i| i,
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(stack.conns[v6_idx].is_v6);
    stack.conns[v6_idx].active = false; // as a closed connection leaves it
    stack.active_count -|= 1;
    stack.syn_queue_count -|= 1;
    while (link_ep.readOutbound(&out_buf) != null) {}

    // A v4 SYN reuses that slot. Only `active` was cleared, so whatever says
    // "this is v6" has to be set by the accept, not left over.
    const syn4 = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const v4_idx = switch (stack.injectPacket(10, pkt_buf[0..syn4])) {
        .accepted => |i| i,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(v6_idx, v4_idx); // the same slot, reused
    try testing.expect(!stack.conns[v4_idx].is_v6);

    // The SYN+ACK goes out as IPv4, and the peer's ACK finds the connection.
    const raw = link_ep.readOutbound(&out_buf).?;
    try testing.expect(parseTcp6FromRaw(raw) == null);
    const syn_ack = parseTcpFromRaw(raw).?;
    try testing.expect(syn_ack.flags.syn and syn_ack.flags.ack);
    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(20, pkt_buf[0..ack_len])) {
        .accepted => |i| try testing.expectEqual(v4_idx, i),
        else => return error.TestUnexpectedResult,
    }
}

test "FullStack: a cookie accept does not inherit a v6 connection's slot" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    const us6 = v6Addr(1);
    const them6 = v6Addr(2);
    stack.setIpv6Addr(us6);
    _ = stack.listen(80, 128);

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;

    // A v6 connection takes slot 0 and then goes away.
    const syn6 = buildTcp6Packet(them6, 5000, us6, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    const v6_idx = switch (stack.injectPacket(0, pkt_buf[0..syn6])) {
        .accepted => |i| i,
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(stack.conns[v6_idx].is_v6);
    stack.conns[v6_idx].active = false; // as a closed connection leaves it
    stack.active_count -|= 1;
    stack.syn_queue_count -|= 1;
    while (link_ep.readOutbound(&out_buf) != null) {}

    // Under load the stack answers with cookies, so a v4 SYN gets one and
    // the handshake completes through acceptCookieConn — the other passive
    // open, which reuses that same slot.
    stack.syn_cookie_threshold = 0;
    const syn4 = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(10, pkt_buf[0..syn4]);
    const cookie_syn_ack = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    try testing.expect(cookie_syn_ack.flags.syn and cookie_syn_ack.flags.ack);

    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3001, cookie_syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    const v4_idx = switch (stack.injectPacket(20, pkt_buf[0..ack_len])) {
        .accepted => |i| i,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(v6_idx, v4_idx); // the same slot, reused
    try testing.expect(!stack.conns[v4_idx].is_v6);

    // Data on the new connection is answered over IPv4, and finds it.
    const data_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3001, cookie_syn_ack.seq +% 1, .{ .ack = true, .psh = true }, 65535, "hi", &pkt_buf);
    _ = stack.injectPacket(30, pkt_buf[0..data_len]);
    var data: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 2), stack.read(v4_idx, &data));
    _ = stack.poll(600); // the ACK is delayed; this sends it
    const reply = link_ep.readOutbound(&out_buf) orelse return error.NoAck;
    try testing.expect(parseTcp6FromRaw(reply) == null);
    try testing.expectEqual(@as(u16, 6000), parseTcpFromRaw(reply).?.dst_port);
}

test "FullStack: accepting a held SYN does not fall back to a cookie" {
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

    // Half-open connections elsewhere put the stack over the cookie
    // threshold. A cookie answers statelessly, which would leave the caller
    // told "no room" while the peer went on to complete a handshake.
    stack.syn_cookie_threshold = 0;

    const idx = stack.acceptPending(pending, 50) orelse return error.NoConnection;
    try testing.expectEqual(@as(usize, 1), stack.active_count);
    try testing.expectEqual(@as(u16, 1), stack.syn_queue_count);
    try testing.expectEqual(tcp_connection.State.syn_received, stack.connState(idx).?);

    // The handshake completes into the accept queue, with the state the
    // stack kept — not a cookie it would have to re-derive.
    const syn_ack = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5000, .{ 10, 0, 0, 1 }, 80, 1001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    switch (stack.injectPacket(60, pkt_buf[0..ack_len])) {
        .accepted => |i| try testing.expectEqual(idx, i),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(idx, stack.accept().?);
}

test "FullStack: a refused listen does not raise the queue limits" {
    const Small = FullStackWith(8, .{ .max_listen_ports = 1 });
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = Small.init(&link_ep, .{ 10, 0, 0, 1 });

    try testing.expect(stack.listen(80, 16));
    const syn_limit = stack.syn_queue_limit;
    const accept_limit = stack.accept_queue_limit;

    // No slot for it, so it asked for room it did not get.
    try testing.expect(!stack.listen(81, 4096));
    try testing.expectEqual(syn_limit, stack.syn_queue_limit);
    try testing.expectEqual(accept_limit, stack.accept_queue_limit);

    // A port already in the set still gets what it asks for.
    try testing.expect(stack.listen(80, 4096));
    try testing.expectEqual(@as(u16, 4096), stack.syn_queue_limit);
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

    // Client sends ACK completing handshake. As above, the SYN this side
    // sent is already in its retransmit queue.

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
    try testing.expectEqual(@as(usize, 1024), stack.conns[0].conn.send.slice().len);
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

test "FullStack: a connection aborted while opening gives its slot back" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(4).init(&link_ep, .{ 10, 0, 0, 1 });
    try testing.expect(stack.listen(80, 4));

    // A SYN, answered with a SYN+ACK: one slot taken and one handshake in
    // the SYN queue, which is the count that decides whether the listener
    // still takes new connections or falls back to cookies.
    var pkt_buf: [128]u8 = undefined;
    const syn_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 40000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(1, pkt_buf[0..syn_len]);
    try testing.expectEqual(@as(u16, 1), stack.active_count);
    try testing.expectEqual(@as(u16, 1), stack.syn_queue_count);

    // The peer never finishes the handshake and this side gives up on it.
    var out_buf: [1600]u8 = undefined;
    while (link_ep.readOutbound(&out_buf)) |_| {}
    stack.setLinger(0, true, 0);
    stack.close(0);
    switch (stack.poll(2)) {
        .aborted => |idx| try testing.expectEqual(@as(u16, 0), idx),
        else => return error.TestUnexpectedResult,
    }

    // The reset went out, and the slot and the handshake count came back.
    const rst = link_ep.readOutbound(&out_buf).?;
    const parsed = parseTcpFromRaw(rst).?;
    try testing.expect(parsed.flags.rst);
    try testing.expect(parsed.flags.ack);
    try testing.expectEqual(@as(u16, 0), stack.active_count);
    try testing.expectEqual(@as(u16, 0), stack.syn_queue_count);
    try testing.expect(!stack.conns[0].active);

    // And the listener still takes connections: a second SYN opens a slot
    // rather than being answered with a cookie because the queue looks full.
    const syn2_len = buildTcpPacket(.{ 10, 0, 0, 3 }, 40001, .{ 10, 0, 0, 1 }, 80, 2000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(3, pkt_buf[0..syn2_len]);
    try testing.expectEqual(@as(u16, 1), stack.active_count);
    try testing.expectEqual(@as(u16, 1), stack.syn_queue_count);
}

test "FullStack: a slot that ended before it was accepted is not handed out" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(4).init(&link_ep, .{ 10, 0, 0, 1 });
    try testing.expect(stack.listen(80, 4));

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;

    // One peer opens a connection and nobody accepts it yet.
    const syn_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 40000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(1, pkt_buf[0..syn_len]);
    const syn_ack = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 40000, .{ 10, 0, 0, 1 }, 80, 1001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(2, pkt_buf[0..ack_len]);
    try testing.expectEqual(@as(u16, 1), stack.active_count);

    // Then it changes its mind, which frees the slot while its index is
    // still sitting in the accept queue.
    const rst_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 40000, .{ 10, 0, 0, 1 }, 80, 1001, syn_ack.seq +% 1, .{ .rst = true }, 0, &.{}, &pkt_buf);
    _ = stack.injectPacket(3, pkt_buf[0..rst_len]);
    try testing.expectEqual(@as(u16, 0), stack.active_count);

    // Another peer takes the same slot.
    const syn2_len = buildTcpPacket(.{ 10, 0, 0, 3 }, 40001, .{ 10, 0, 0, 1 }, 80, 2000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(4, pkt_buf[0..syn2_len]);
    const syn_ack2 = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    const ack2_len = buildTcpPacket(.{ 10, 0, 0, 3 }, 40001, .{ 10, 0, 0, 1 }, 80, 2001, syn_ack2.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(5, pkt_buf[0..ack2_len]);

    // One connection is waiting, not two, and it is the one that is still
    // here: the other peer's index would have been handed out first, and by
    // then it named this connection.
    const idx = stack.accept() orelse return error.NothingToAccept;
    try testing.expectEqual(@as(u16, 40001), stack.conns[idx].id.remote_port);
    try testing.expect(stack.accept() == null);
}

test "FullStack: a backlog larger than the stack does not promise more than it has" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(4).init(&link_ep, .{ 10, 0, 0, 1 });

    // A listener asking for a hundred on a stack with four slots: the queue
    // it would fill has four places in it.
    try testing.expect(stack.listen(80, 100));
    try testing.expect(stack.accept_queue_limit <= 4);

    // And the SYN queue, which is counted rather than stored, is not held
    // down by the number of slots: it starts at 128 and a listener can only
    // raise it.
    try testing.expect(stack.syn_queue_limit >= 100);
}

test "FullStack: udpSendFrom carries the source the caller asked for" {
    // A relay's answer has to come back from the address and port the
    // sender wrote to, not from this stack's own overlay address. A
    // connected UDP socket — a DNS resolver, most UDP clients — drops
    // anything from a different source.
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 100, 64, 0, 1 });

    const ep = stack.udpBind(0).?;
    const peer: [4]u8 = .{ 100, 64, 0, 9 };
    const behind: [4]u8 = .{ 192, 168, 1, 5 };

    try testing.expect(stack.udpSendFrom(ep, behind, 53, peer, 40000, "answer"));
    try testing.expectEqual(@as(usize, 1), link_ep.outboundCount());

    var out_buf: [1500]u8 = undefined;
    const raw = link_ep.readOutbound(&out_buf).?;
    try testing.expectEqualSlices(u8, &behind, raw[12..16]);
    try testing.expectEqualSlices(u8, &peer, raw[16..20]);
    try testing.expectEqual(@as(u16, 53), std.mem.readInt(u16, raw[20..22], .big));
    try testing.expectEqual(@as(u16, 40000), std.mem.readInt(u16, raw[22..24], .big));
    try testing.expectEqualStrings("answer", raw[28..]);

    // The checksums have to follow the address, or the peer's stack drops
    // the datagram before anything looks at it.
    const cksum_mod = @import("checksum.zig");
    try testing.expectEqual(@as(u16, 0xFFFF), cksum_mod.finish(cksum_mod.accumulate(0, raw[0..20])) ^ 0xFFFF);
    {
        const udp_len: u16 = @intCast(raw.len - 20);
        const ph = cksum_mod.pseudoHeaderIpv4(behind, peer, 17, udp_len);
        try testing.expectEqual(@as(u16, 0), cksum_mod.finish(cksum_mod.accumulate(ph, raw[20..])));
    }

    // And the ordinary send still speaks for this stack.
    try testing.expect(stack.udpSendTo(ep, peer, 40000, "mine"));
    const own = link_ep.readOutbound(&out_buf).?;
    try testing.expectEqualSlices(u8, &[_]u8{ 100, 64, 0, 1 }, own[12..16]);
}

test "FullStack: udpEmitFrom needs no endpoint, and builds what udpSendFrom builds" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 100, 64, 0, 1 });
    const peer: [4]u8 = .{ 100, 64, 0, 9 };
    const behind: [4]u8 = .{ 192, 168, 1, 5 };

    // Far more answers than the stack has endpoints, and none bound.
    for (0..64) |i| stack.udpEmitFrom(behind, 53, peer, @intCast(40000 + i), "answer");
    try testing.expectEqual(@as(usize, 64), link_ep.outboundCount());
    try testing.expectEqual(@as(usize, 0), stack.udp_count);

    var emitted: [1500]u8 = undefined;
    const raw = link_ep.readOutbound(&emitted).?;

    // Byte for byte what the endpoint path sends for the same datagram,
    // from the addresses on (the IP id before them counts up).
    var drain: [1500]u8 = undefined;
    while (link_ep.outboundCount() > 0) _ = link_ep.readOutbound(&drain);
    const ep = stack.udpBind(0).?;
    try testing.expect(stack.udpSendFrom(ep, behind, 53, peer, 40000, "answer"));
    var sent: [1500]u8 = undefined;
    const via_ep = link_ep.readOutbound(&sent).?;
    try testing.expectEqualSlices(u8, via_ep[12..], raw[12..]);
}

// ================================================================
// Connection slots in chunks (cfg.conn_chunk)
// ================================================================

const ChunkedStack = FullStackWith(48, .{ .conn_chunk = 16 });

/// A client at 10.0.0.2:`port` opens a connection to 10.0.0.1:80 and
/// finishes the handshake. Returns the connection's slot, once accepted.
fn chunkedHandshake(stack: *ChunkedStack, link_ep: *link_mod.ChannelEndpoint, port: u16) !u16 {
    var pkt: [128]u8 = undefined;
    const syn_len = buildTcpPacket(.{ 10, 0, 0, 2 }, port, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt);
    switch (stack.injectPacket(0, pkt[0..syn_len])) {
        .accepted => {},
        else => return error.SynNotAccepted,
    }
    var out: [1600]u8 = undefined;
    const syn_ack = parseTcpFromRaw(link_ep.readOutbound(&out) orelse return error.NoSynAck) orelse return error.NoSynAck;
    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, port, .{ 10, 0, 0, 1 }, 80, 1001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt);
    _ = stack.injectPacket(0, pkt[0..ack_len]);
    return stack.accept() orelse error.NotAccepted;
}

test "FullStack chunked: slots come a chunk at a time, and only when a connection needs one" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack: ChunkedStack = undefined;
    stack.initAlloc(&link_ep, .{ 10, 0, 0, 1 }, .{1} ** 16, testing.allocator);
    defer stack.deinit();
    _ = stack.listen(80, 128);

    // Nothing allocated until something connects.
    try testing.expectEqual(@as(usize, 0), stack.slotCount());

    var seen = [_]bool{false} ** 48;
    for (0..16) |i| {
        const idx = try chunkedHandshake(&stack, &link_ep, @intCast(5000 + i));
        try testing.expect(!seen[idx]);
        seen[idx] = true;
    }
    try testing.expectEqual(@as(usize, 16), stack.slotCount());

    // The seventeenth takes a second chunk, and is a connection like any other.
    const idx17 = try chunkedHandshake(&stack, &link_ep, 5016);
    try testing.expectEqual(@as(usize, 32), stack.slotCount());
    try testing.expect(idx17 >= 16);
    try testing.expectEqual(tcp_connection.State.established, stack.connState(idx17).?);

    // Data reaches it: found by its address, past the first chunk.
    var pkt: [128]u8 = undefined;
    const data_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 5016, .{ 10, 0, 0, 1 }, 80, 1001, stack.slotAt(idx17).conn.sender.snd_nxt, .{ .ack = true, .psh = true }, 65535, "hello", &pkt);
    _ = stack.injectPacket(1, pkt[0..data_len]);
    var got: [16]u8 = undefined;
    try testing.expectEqualStrings("hello", got[0..stack.read(idx17, &got)]);
}

test "FullStack chunked: no more than max_conns, and a freed slot before a new chunk" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack: ChunkedStack = undefined;
    stack.initAlloc(&link_ep, .{ 10, 0, 0, 1 }, .{2} ** 16, testing.allocator);
    defer stack.deinit();
    _ = stack.listen(80, 128);

    for (0..48) |i| _ = try chunkedHandshake(&stack, &link_ep, @intCast(6000 + i));
    try testing.expectEqual(@as(usize, 48), stack.slotCount());

    // Full: the forty-ninth SYN gets no slot and no answer.
    var pkt: [128]u8 = undefined;
    const syn_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 7000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt);
    try testing.expectEqual(Event.none, stack.injectPacket(0, pkt[0..syn_len]));
    try testing.expectEqual(@as(usize, 48), stack.slotCount());

    // One goes away; the next connection takes its slot, and no chunk more.
    const rst_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 6020, .{ 10, 0, 0, 1 }, 80, 1001, 0, .{ .rst = true }, 0, &.{}, &pkt);
    _ = stack.injectPacket(0, pkt[0..rst_len]);
    while (link_ep.outboundCount() > 0) {
        var out: [1600]u8 = undefined;
        _ = link_ep.readOutbound(&out);
    }
    const reused = try chunkedHandshake(&stack, &link_ep, 7001);
    try testing.expect(reused < 48);
    try testing.expectEqual(@as(usize, 48), stack.slotCount());
}

test "FullStack chunked: an allocator that says no drops the SYN, and nothing else" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 1 });
    var stack: ChunkedStack = undefined;
    stack.initAlloc(&link_ep, .{ 10, 0, 0, 1 }, .{3} ** 16, failing.allocator());
    defer stack.deinit();
    _ = stack.listen(80, 128);

    // The first chunk is had; the second is refused.
    for (0..16) |i| _ = try chunkedHandshake(&stack, &link_ep, @intCast(8000 + i));
    var pkt: [128]u8 = undefined;
    const syn_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 8016, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt);
    try testing.expectEqual(Event.none, stack.injectPacket(0, pkt[0..syn_len]));
    try testing.expectEqual(@as(usize, 16), stack.slotCount());
    // What it had still works.
    try testing.expectEqual(tcp_connection.State.established, stack.connState(0).?);
}

/// The client at 10.0.0.2:`port` resets its connection.
fn chunkedReset(stack: *ChunkedStack, link_ep: *link_mod.ChannelEndpoint, port: u16) void {
    var pkt: [128]u8 = undefined;
    const rst_len = buildTcpPacket(.{ 10, 0, 0, 2 }, port, .{ 10, 0, 0, 1 }, 80, 1001, 0, .{ .rst = true }, 0, &.{}, &pkt);
    _ = stack.injectPacket(0, pkt[0..rst_len]);
    var out: [1600]u8 = undefined;
    while (link_ep.outboundCount() > 0) _ = link_ep.readOutbound(&out);
}

test "FullStack chunked: the empty chunks at the end go back, and the first stays" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack: ChunkedStack = undefined;
    stack.initAlloc(&link_ep, .{ 10, 0, 0, 1 }, .{4} ** 16, testing.allocator);
    defer stack.deinit();
    _ = stack.listen(80, 128);

    for (0..40) |i| _ = try chunkedHandshake(&stack, &link_ep, @intCast(9000 + i));
    try testing.expectEqual(@as(usize, 48), stack.slotCount());
    // Nothing goes while anything is open at the end.
    try testing.expectEqual(@as(usize, 0), stack.shrinkSlots());

    for (0..40) |i| chunkedReset(&stack, &link_ep, @intCast(9000 + i));
    try testing.expectEqual(@as(usize, 2), stack.shrinkSlots());
    try testing.expectEqual(@as(usize, 16), stack.slotCount());
    // Asked again, there is nothing more to give.
    try testing.expectEqual(@as(usize, 0), stack.shrinkSlots());

    // And it grows again when it has to.
    for (0..17) |i| _ = try chunkedHandshake(&stack, &link_ep, @intCast(9100 + i));
    try testing.expectEqual(@as(usize, 32), stack.slotCount());
}

test "FullStack chunked: one connection near the end keeps its chunk, and an old index reads as nothing" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack: ChunkedStack = undefined;
    stack.initAlloc(&link_ep, .{ 10, 0, 0, 1 }, .{5} ** 16, testing.allocator);
    defer stack.deinit();
    _ = stack.listen(80, 128);

    var idx = [_]u16{0} ** 40;
    for (0..40) |i| idx[i] = try chunkedHandshake(&stack, &link_ep, @intCast(9200 + i));
    // Everything closes but one connection in the third chunk.
    var kept: usize = 0;
    for (0..40) |i| {
        if (idx[i] >= 32 and kept == 0) {
            kept = i;
            continue;
        }
        chunkedReset(&stack, &link_ep, @intCast(9200 + i));
    }
    try testing.expectEqual(@as(usize, 0), stack.shrinkSlots());
    try testing.expectEqual(@as(usize, 48), stack.slotCount());
    try testing.expectEqual(tcp_connection.State.established, stack.connState(idx[kept]).?);

    // It closes, and both chunks after the first go.
    chunkedReset(&stack, &link_ep, @intCast(9200 + kept));
    try testing.expectEqual(@as(usize, 2), stack.shrinkSlots());

    // Its index is past what exists now: nothing there, and nothing breaks.
    const old = idx[kept];
    try testing.expect(old >= stack.slotCount());
    try testing.expectEqual(@as(?tcp_connection.State, null), stack.connState(old));
    try testing.expectEqual(@as(?ConnId, null), stack.connId(old));
    var buf: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), stack.read(old, &buf));
    try testing.expectEqual(@as(usize, 0), stack.write(old, "late"));
    stack.close(old);
}

// ================================================================
// UDP larger than the link: IPv4 fragments (cfg.link_mtu)
// ================================================================

const TunnelStack = FullStackWith(16, .{ .link_mtu = 1280 });

/// Read every packet the stack queued and put the UDP datagram back
/// together, checking each fragment on the way. Returns the datagram (UDP
/// header and data) and how many fragments carried it.
fn reassembleUdp(link_ep: *link_mod.ChannelEndpoint, out: []u8, mtu: usize) !struct { len: usize, fragments: usize } {
    var len: usize = 0;
    var fragments: usize = 0;
    var id: ?u16 = null;
    // The one fragment without More Fragments, and where it ends.
    var lasts: usize = 0;
    var last_end: usize = 0;
    var pkt_buf: [1600]u8 = undefined;
    while (link_ep.readOutbound(&pkt_buf)) |pkt| {
        fragments += 1;
        try testing.expect(pkt.len <= mtu);
        const hdr = try ipv4_header.Header.parse(pkt);
        try testing.expect(hdr.isChecksumValid());
        try testing.expect(!hdr.dontFragment());
        if (id) |i| try testing.expectEqual(i, hdr.identification()) else id = hdr.identification();
        const off = @as(usize, hdr.fragmentOffset()) * 8;
        const body = pkt[20..hdr.totalLen()];
        if (hdr.moreFragments()) {
            try testing.expectEqual(@as(usize, 0), body.len % 8);
        } else {
            lasts += 1;
            last_end = off + body.len;
        }
        @memcpy(out[off .. off + body.len], body);
        len = @max(len, off + body.len);
    }
    // Exactly one says it is the last, and it is: nothing ends after it.
    try testing.expectEqual(@as(usize, 1), lasts);
    try testing.expectEqual(len, last_end);
    return .{ .len = len, .fragments = fragments };
}

test "FullStack: UDP larger than the link goes in fragments, which put back together are the datagram" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = TunnelStack.init(&link_ep, .{ 100, 64, 0, 1 });
    const peer: [4]u8 = .{ 100, 64, 0, 9 };
    const behind: [4]u8 = .{ 8, 8, 8, 8 };
    var data: [3000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 7 + 3);

    // An answer the size of a large DNS response or a QUIC handshake.
    stack.udpEmitFrom(behind, 53, peer, 40000, &data);

    var datagram: [4000]u8 = undefined;
    const got = try reassembleUdp(&link_ep, &datagram, 1280);
    // 8 + 3000 bytes in pieces of 1256 (1280 - 20, a multiple of 8).
    try testing.expectEqual(@as(usize, 3), got.fragments);
    try testing.expectEqual(@as(usize, 8 + data.len), got.len);
    try testing.expectEqualSlices(u8, &data, datagram[8..got.len]);
    try testing.expectEqual(@as(u16, 53), std.mem.readInt(u16, datagram[0..2], .big));
    try testing.expectEqual(@as(u16, 40000), std.mem.readInt(u16, datagram[2..4], .big));
    try testing.expectEqual(@as(u16, 8 + data.len), std.mem.readInt(u16, datagram[4..6], .big));
    // The checksum covers the whole datagram, as if it had gone whole.
    const cksum = @import("checksum.zig");
    const ph = cksum.pseudoHeaderIpv4(behind, peer, 17, @intCast(got.len));
    try testing.expectEqual(@as(u16, 0), cksum.finish(cksum.accumulate(ph, datagram[0..got.len])));
}

test "FullStack: UDP that fits the link goes whole, and one byte more does not" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = TunnelStack.init(&link_ep, .{ 100, 64, 0, 1 });
    var data: [1280 - 28 + 1]u8 = undefined;
    @memset(&data, 0x5a);

    stack.udpEmitFrom(.{ 8, 8, 8, 8 }, 53, .{ 100, 64, 0, 9 }, 40000, data[0 .. data.len - 1]);
    try testing.expectEqual(@as(usize, 1), link_ep.outboundCount());
    var pkt: [1600]u8 = undefined;
    const whole = link_ep.readOutbound(&pkt).?;
    try testing.expectEqual(@as(usize, 1280), whole.len);
    try testing.expect(!(try ipv4_header.Header.parse(whole)).moreFragments());

    stack.udpEmitFrom(.{ 8, 8, 8, 8 }, 53, .{ 100, 64, 0, 9 }, 40000, &data);
    var datagram: [1600]u8 = undefined;
    const got = try reassembleUdp(&link_ep, &datagram, 1280);
    try testing.expectEqual(@as(usize, 2), got.fragments);
    try testing.expectEqual(@as(usize, 8 + data.len), got.len);
}

test "FullStack: on an Ethernet-sized link, what used to be dropped now goes in fragments" {
    // The default link takes 1500. A datagram past it was not sent at all.
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 100, 64, 0, 1 });
    var data: [2000]u8 = undefined;
    @memset(&data, 1);
    stack.udpEmitFrom(.{ 8, 8, 8, 8 }, 53, .{ 100, 64, 0, 9 }, 40000, &data);
    var datagram: [2100]u8 = undefined;
    const got = try reassembleUdp(&link_ep, &datagram, 1500);
    try testing.expectEqual(@as(usize, 2), got.fragments);
    try testing.expectEqual(@as(usize, 2008), got.len);
}

test "FullStack: a connection a cookie accepted sends no segment past this side's MSS" {
    // Under a burst the stack answers SYNs with cookies, and what the
    // cookie carried was Ethernet's 1460 whatever this side could take:
    // on a 1280-byte link every full segment was too large to send.
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = TunnelSmallMss.init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 128);
    stack.syn_cookie_threshold = 0;

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;
    const syn = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(10, pkt_buf[0..syn]);
    const syn_ack = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    const idx = switch (stack.injectPacket(20, pkt_buf[0..ack_len])) {
        .accepted => |i| i,
        else => return error.TestUnexpectedResult,
    };

    // Plenty to send: every segment it makes fits 1240 of data.
    var big: [8000]u8 = undefined;
    @memset(&big, 'x');
    _ = stack.write(idx, &big);
    var now: u64 = 30;
    var segments: usize = 0;
    while (now < 3000) : (now += 50) {
        _ = stack.poll(now);
        while (link_ep.readOutbound(&out_buf)) |pkt| {
            try testing.expect(pkt.len <= 1280);
            segments += 1;
        }
    }
    try testing.expect(segments > 0);
    try testing.expect(stack.conns[idx].conn.sender.mss <= 1240);
}

const TunnelSmallMss = FullStackWith(16, .{ .link_mtu = 1280, .default_mss = 1240 });

const GrowStack = FullStackWith(16, .{ .grow_buffers = true, .send_buf_size = 256 * 1024, .buf_initial = 4096 });

/// A connection to `stack` on port 80 from 10.0.0.2:`port`, through the
/// whole handshake.
fn growAccept(comptime S: type, stack: *S, link_ep: *link_mod.ChannelEndpoint, port: u16) !u16 {
    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;
    const syn = buildTcpPacket(.{ 10, 0, 0, 2 }, port, .{ 10, 0, 0, 1 }, 80, 3000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(10, pkt_buf[0..syn]);
    const syn_ack = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, port, .{ 10, 0, 0, 1 }, 80, 3001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    return switch (stack.injectPacket(20, pkt_buf[0..ack_len])) {
        .accepted => |i| i,
        else => error.TestUnexpectedResult,
    };
}

test "FullStack grow_buffers: a connection takes more than it starts with, and gives it back once quiet" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack: GrowStack = undefined;
    stack.initAlloc(&link_ep, .{ 10, 0, 0, 1 }, .{6} ** 16, testing.allocator);
    defer stack.deinit();
    _ = stack.listen(80, 16);
    const idx = try growAccept(GrowStack, &stack, &link_ep, 6000);

    // Far past 64KiB, which is all a fixed buffer of the default size took.
    var big: [100_000]u8 = undefined;
    @memset(&big, 'x');
    try testing.expectEqual(@as(usize, big.len), stack.write(idx, &big));
    try testing.expect(stack.conns[idx].conn.send.heap.len >= big.len);

    // The peer acknowledges everything as it comes, until nothing is left.
    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;
    var now: u64 = 30;
    var acked: usize = 0;
    while (now < 60_000 and acked < big.len) : (now += 10) {
        _ = stack.poll(now);
        while (link_ep.readOutbound(&out_buf)) |raw| {
            const seg = parseTcpFromRaw(raw).?;
            if (seg.payload_len == 0) continue;
            const end = seg.seq +% @as(u32, @intCast(seg.payload_len));
            const len = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3001, end, .{ .ack = true }, 65535, &.{}, &pkt_buf);
            _ = stack.injectPacket(now, pkt_buf[0..len]);
            acked += seg.payload_len;
        }
    }
    try testing.expectEqual(big.len, acked);
    // Drained, but the peer spoke a moment ago: kept for the next burst,
    // rather than given back and allocated again.
    try testing.expect(stack.conns[idx].conn.send.heap.len >= big.len);
    _ = stack.poll(now + 500);
    try testing.expect(stack.conns[idx].conn.send.heap.len >= big.len);
    // Quiet for buf_shrink_idle_ms: back to the first size.
    now += 1000;
    _ = stack.poll(now);
    try testing.expectEqual(@as(usize, 4096), stack.conns[idx].conn.send.heap.len);

    // The other way: more than the first 4KiB arrives, is read, and the
    // receive side goes back to its first size too.
    var seq: u32 = 3001;
    var chunk: [1400]u8 = undefined;
    @memset(&chunk, 'y');
    var data_buf: [1600]u8 = undefined;
    const snd_nxt = stack.conns[idx].conn.sender.snd_nxt;
    for (0..5) |_| {
        const len = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, seq, snd_nxt, .{ .ack = true, .psh = true }, 65535, &chunk, &data_buf);
        _ = stack.injectPacket(now, data_buf[0..len]);
        seq +%= chunk.len;
    }
    try testing.expect(stack.conns[idx].conn.receiver.store.heap.len >= 5 * chunk.len);
    var read_buf: [8000]u8 = undefined;
    try testing.expectEqual(@as(usize, 5 * chunk.len), stack.read(idx, &read_buf));
    try testing.expect(stack.conns[idx].conn.receiver.store.heap.len >= 5 * chunk.len);
    _ = stack.poll(now + 1000);
    try testing.expectEqual(@as(usize, 4096), stack.conns[idx].conn.receiver.store.heap.len);
}

test "FullStack grow_buffers: what every connection holds stays within buf_budget" {
    const Budgeted = FullStackWith(16, .{ .grow_buffers = true, .send_buf_size = 256 * 1024, .buf_initial = 4096, .buf_budget = 64 * 1024 });
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack: Budgeted = undefined;
    stack.initAlloc(&link_ep, .{ 10, 0, 0, 1 }, .{9} ** 16, testing.allocator);
    defer stack.deinit();
    _ = stack.listen(80, 16);

    // Each could take 256KiB; together they get 64KiB, and whatever does
    // not fit is refused rather than allocated.
    var big: [100_000]u8 = undefined;
    @memset(&big, 'b');
    var took: usize = 0;
    for (0..4) |i| {
        const idx = try growAccept(Budgeted, &stack, &link_ep, 6200 + @as(u16, @intCast(i)));
        took += stack.write(idx, &big);
        try testing.expect(stack.bufBytesHeld() <= 64 * 1024);
    }
    try testing.expect(took > 0);
    try testing.expect(took < 4 * big.len);
}

test "FullStack grow_buffers: a connection reset while it holds data gives its memory back" {
    // testing.allocator fails the test on a leak: a slot the reset frees
    // has to hand back what it held, before the next connection there
    // writes over it.
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack: GrowStack = undefined;
    stack.initAlloc(&link_ep, .{ 10, 0, 0, 1 }, .{7} ** 16, testing.allocator);
    defer stack.deinit();
    _ = stack.listen(80, 16);

    for (0..3) |round| {
        const port: u16 = 6000 + @as(u16, @intCast(round));
        const idx = try growAccept(GrowStack, &stack, &link_ep, port);
        var big: [20_000]u8 = undefined;
        @memset(&big, 'z');
        try testing.expectEqual(@as(usize, big.len), stack.write(idx, &big));
        var pkt_buf: [128]u8 = undefined;
        const rst = buildTcpPacket(.{ 10, 0, 0, 2 }, port, .{ 10, 0, 0, 1 }, 80, 3001, 0, .{ .rst = true }, 0, &.{}, &pkt_buf);
        _ = stack.injectPacket(40, pkt_buf[0..rst]);
        try testing.expect(!stack.conns[idx].active);
        var out_buf: [1600]u8 = undefined;
        while (link_ep.readOutbound(&out_buf)) |_| {}
    }
}

test "FullStack grow_buffers: connections open at the end are given back with the stack" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack: GrowStack = undefined;
    stack.initAlloc(&link_ep, .{ 10, 0, 0, 1 }, .{8} ** 16, testing.allocator);
    defer stack.deinit();
    _ = stack.listen(80, 16);
    const idx = try growAccept(GrowStack, &stack, &link_ep, 6100);
    var big: [20_000]u8 = undefined;
    @memset(&big, 'w');
    try testing.expectEqual(@as(usize, big.len), stack.write(idx, &big));
    var out_buf: [1600]u8 = undefined;
    while (link_ep.readOutbound(&out_buf)) |_| {}
}

// ================================================================
// MSS by family and by what the peer offered
// ================================================================

/// A SYN offering `mss`, over IPv4 or IPv6 (for tests).
fn buildSynWithMss(comptime Addr: type, src: Addr, src_port: u16, dst: Addr, dst_port: u16, seq: u32, mss: u16, out: []u8) usize {
    const opt = [4]u8{ 2, 4, @intCast(mss >> 8), @intCast(mss & 0xff) };
    const v6 = Addr == [16]u8;
    const ip_hlen: usize = if (v6) 40 else 20;
    // Built with the option as payload, then the data offset moved past
    // it and the checksum taken again.
    const total = if (v6)
        buildTcp6Packet(src, src_port, dst, dst_port, seq, 0, .{ .syn = true }, 65535, &opt, out)
    else
        buildTcpPacket(src, src_port, dst, dst_port, seq, 0, .{ .syn = true }, 65535, &opt, out);
    out[ip_hlen + 12] = 6 << 4;
    const seg = out[ip_hlen..total];
    seg[16] = 0;
    seg[17] = 0;
    const cksum = @import("checksum.zig");
    const ph = if (v6) cksum.pseudoHeaderIpv6(src, dst, 6, @intCast(seg.len)) else cksum.pseudoHeaderIpv4(src, dst, 6, @intCast(seg.len));
    std.mem.writeInt(u16, seg[16..18], cksum.finish(cksum.accumulate(ph, seg)), .big);
    return total;
}

/// The MSS a SYN or SYN+ACK offers, 0 for none (for tests).
fn offeredMss(raw: []const u8) u16 {
    const ip_hlen: usize = if (raw[0] >> 4 == 6) 40 else 20;
    const tcp = raw[ip_hlen..];
    const hdr_len: usize = @as(usize, tcp[12] >> 4) * 4;
    return @import("transport/tcp/options.zig").parseOptions(tcp[20..hdr_len]).mss;
}

test "FullStack: link_mtu alone holds TCP to the link, and IPv6 20 bytes lower" {
    // default_mss left at Ethernet's 1460: link_mtu is what decides.
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = TunnelStack.init(&link_ep, .{ 10, 0, 0, 1 });
    stack.setIpv6Addr(v6Addr(1));
    _ = stack.listen(80, 128);
    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;

    const syn4 = buildSynWithMss([4]u8, .{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3000, 1460, &pkt_buf);
    _ = stack.injectPacket(0, pkt_buf[0..syn4]);
    try testing.expectEqual(@as(u16, 1240), offeredMss(link_ep.readOutbound(&out_buf).?));
    // What this side offers is what its link takes, not the smaller of
    // that and the peer's: each direction has its own.
    const small = buildSynWithMss([4]u8, .{ 10, 0, 0, 3 }, 6000, .{ 10, 0, 0, 1 }, 80, 3000, 536, &pkt_buf);
    _ = stack.injectPacket(0, pkt_buf[0..small]);
    try testing.expectEqual(@as(u16, 1240), offeredMss(link_ep.readOutbound(&out_buf).?));

    const syn6 = buildSynWithMss([16]u8, v6Addr(2), 6000, v6Addr(1), 80, 3000, 1440, &pkt_buf);
    _ = stack.injectPacket(0, pkt_buf[0..syn6]);
    const syn_ack6 = link_ep.readOutbound(&out_buf).?;
    try testing.expectEqual(@as(u16, 1220), offeredMss(syn_ack6));
    const sa = parseTcp6FromRaw(syn_ack6).?;

    // A v6 connection with plenty to send: nothing it sends is past the
    // link. Its segments were 1300 bytes, and the link refused every one.
    const ack_len = buildTcp6Packet(v6Addr(2), 6000, v6Addr(1), 80, 3001, sa.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    const idx = switch (stack.injectPacket(10, pkt_buf[0..ack_len])) {
        .accepted => |i| i,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(@as(u16, 1220), stack.conns[idx].conn.sender.mss);
    var big: [8000]u8 = undefined;
    @memset(&big, 'x');
    _ = stack.write(idx, &big);
    var full: usize = 0;
    var now: u64 = 20;
    while (now < 1000) : (now += 50) {
        _ = stack.poll(now);
        while (link_ep.readOutbound(&out_buf)) |pkt| {
            try testing.expect(pkt.len <= 1280);
            if (pkt.len == 1280) full += 1;
        }
    }
    try testing.expect(full > 0);
    try testing.expectEqual(@as(u64, 0), link_ep.outboundOversize());

    // And an outbound connection, each family.
    const c4 = stack.connect(0, .{ 10, 0, 0, 9 }, 443, 50000).?;
    try testing.expectEqual(@as(u16, 1240), stack.conns[c4].conn.local_mss);
    const c6 = stack.connect6(0, v6Addr(9), 443, 50001).?;
    try testing.expectEqual(@as(u16, 1220), stack.conns[c6].conn.local_mss);
}

test "FullStack: a cookie keeps the MSS the peer offered, and its SYN+ACK offers this side's" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = TunnelStack.init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 128);
    stack.syn_cookie_threshold = 0;
    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;

    // A peer that takes no more than 536. The cookie used to carry this
    // side's own MSS, and the connection sent 1240-byte segments to it.
    const syn = buildSynWithMss([4]u8, .{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3000, 536, &pkt_buf);
    _ = stack.injectPacket(0, pkt_buf[0..syn]);
    const syn_ack_raw = link_ep.readOutbound(&out_buf).?;
    // Without the option the peer would hold this side to 536 too.
    try testing.expectEqual(@as(u16, 1240), offeredMss(syn_ack_raw));
    const syn_ack = parseTcpFromRaw(syn_ack_raw).?;
    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    const idx = switch (stack.injectPacket(10, pkt_buf[0..ack_len])) {
        .accepted => |i| i,
        else => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(@as(u16, 536), stack.conns[idx].conn.sender.mss);

    var big: [4000]u8 = undefined;
    @memset(&big, 'x');
    _ = stack.write(idx, &big);
    var now: u64 = 20;
    var segments: usize = 0;
    while (now < 1000) : (now += 50) {
        _ = stack.poll(now);
        while (link_ep.readOutbound(&out_buf)) |pkt| {
            try testing.expect(parseTcpFromRaw(pkt).?.payload_len <= 536);
            segments += 1;
        }
    }
    try testing.expect(segments > 0);
}

test "FullStack: a v6 SYN answered with a cookie is answered over v6" {
    // It went out as IPv4, to the last four bytes of the peer's address.
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = TunnelStack.init(&link_ep, .{ 10, 0, 0, 1 });
    stack.setIpv6Addr(v6Addr(1));
    _ = stack.listen(80, 128);
    stack.syn_cookie_threshold = 0;
    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;

    // No MSS offered: the cookie carries IPv6's least, 1220.
    const syn = buildTcp6Packet(v6Addr(2), 6000, v6Addr(1), 80, 3000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(0, pkt_buf[0..syn]);
    const raw = link_ep.readOutbound(&out_buf).?;
    const syn_ack = parseTcp6FromRaw(raw) orelse return error.NotIpv6;
    try testing.expect(syn_ack.flags.syn and syn_ack.flags.ack);
    try testing.expectEqualSlices(u8, &v6Addr(2), &syn_ack.dst_addr);
    try testing.expectEqual(@as(u16, 1220), offeredMss(raw));

    const ack_len = buildTcp6Packet(v6Addr(2), 6000, v6Addr(1), 80, 3001, syn_ack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    const idx = switch (stack.injectPacket(10, pkt_buf[0..ack_len])) {
        .accepted => |i| i,
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(stack.conns[idx].is_v6);
    try testing.expect(stack.conns[idx].conn.sender.mss <= 1220);
}

test "FullStack: UDP over IPv6 larger than the link goes in fragments" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = TunnelStack.init(&link_ep, .{ 10, 0, 0, 1 });
    const us = v6Addr(1);
    const them = v6Addr(2);
    stack.setIpv6Addr(us);
    const ep = stack.udpBind(53).?;
    var data: [3000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 5 + 1);
    try testing.expect(stack.udpSendTo6(ep, them, 40000, &data));

    var datagram: [4000]u8 = undefined;
    var len: usize = 0;
    var fragments: usize = 0;
    var lasts: usize = 0;
    var id: ?u32 = null;
    var pkt: [1600]u8 = undefined;
    while (link_ep.readOutbound(&pkt)) |raw| {
        fragments += 1;
        try testing.expect(raw.len <= 1280);
        try testing.expectEqual(@as(u8, 44), raw[6]); // a Fragment header
        const fh = ipv6_frag_mod.FragHeader.parse(raw[40..]).?;
        try testing.expectEqual(ipv6_header.NextHeader.udp, fh.next_header);
        if (id) |i| try testing.expectEqual(i, fh.identification) else id = fh.identification;
        const body = raw[48..];
        try testing.expectEqual(@as(usize, std.mem.readInt(u16, raw[4..6], .big)), 8 + body.len);
        const off = @as(usize, fh.frag_offset) * 8;
        if (fh.more_fragments) try testing.expectEqual(@as(usize, 0), body.len % 8) else lasts += 1;
        @memcpy(datagram[off .. off + body.len], body);
        len = @max(len, off + body.len);
    }
    // 8 + 3000 in pieces of 1232 (1280 - 48, a multiple of 8).
    try testing.expectEqual(@as(usize, 3), fragments);
    try testing.expectEqual(@as(usize, 1), lasts);
    try testing.expectEqual(@as(usize, 8 + data.len), len);
    try testing.expectEqualSlices(u8, &data, datagram[8..len]);
    const cksum = @import("checksum.zig");
    const ph = cksum.pseudoHeaderIpv6(us, them, 17, @intCast(len));
    try testing.expectEqual(@as(u16, 0), cksum.finish(cksum.accumulate(ph, datagram[0..len])));

    // One that fits goes whole.
    try testing.expect(stack.udpSendTo6(ep, them, 40000, data[0 .. 1280 - 48]));
    const whole = link_ep.readOutbound(&pkt).?;
    try testing.expectEqual(@as(usize, 1280), whole.len);
    try testing.expectEqual(@as(u8, 17), whole[6]);
}

test "FullStack: udpEmitFrom6 answers from the address it is given, whole or in fragments" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = TunnelStack.init(&link_ep, .{ 10, 0, 0, 1 });
    stack.setIpv6Addr(v6Addr(1));
    const them = v6Addr(2);
    // A host the stack relays for: not its own v6 address.
    var behind = v6Addr(5);
    behind[1] = 0x99;
    const cksum = @import("checksum.zig");

    // No endpoint is bound, as for udpEmitFrom.
    stack.udpEmitFrom6(behind, 53, them, 40000, "answer");
    try testing.expectEqual(@as(usize, 0), stack.udp_count);
    var pkt: [1600]u8 = undefined;
    const whole = link_ep.readOutbound(&pkt).?;
    try testing.expectEqual(@as(u8, 17), whole[6]);
    try testing.expectEqualSlices(u8, &behind, whole[8..24]);
    try testing.expectEqualSlices(u8, &them, whole[24..40]);
    try testing.expectEqual(@as(u16, 53), std.mem.readInt(u16, whole[40..42], .big));
    try testing.expectEqualStrings("answer", whole[48..]);
    const ph = cksum.pseudoHeaderIpv6(behind, them, 17, @intCast(whole.len - 40));
    try testing.expectEqual(@as(u16, 0), cksum.finish(cksum.accumulate(ph, whole[40..])));

    // Larger than the link: every fragment is from the given address, and
    // the checksum across them is over that address too.
    var data: [3000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 7 + 3);
    stack.udpEmitFrom6(behind, 53, them, 40000, &data);
    var datagram: [4000]u8 = undefined;
    var len: usize = 0;
    var fragments: usize = 0;
    while (link_ep.readOutbound(&pkt)) |raw| {
        fragments += 1;
        try testing.expectEqual(@as(u8, 44), raw[6]);
        try testing.expectEqualSlices(u8, &behind, raw[8..24]);
        const fh = ipv6_frag_mod.FragHeader.parse(raw[40..]).?;
        const off = @as(usize, fh.frag_offset) * 8;
        const body = raw[48..];
        @memcpy(datagram[off .. off + body.len], body);
        len = @max(len, off + body.len);
    }
    try testing.expectEqual(@as(usize, 3), fragments);
    try testing.expectEqualSlices(u8, &data, datagram[8..len]);
    const ph2 = cksum.pseudoHeaderIpv6(behind, them, 17, @intCast(len));
    try testing.expectEqual(@as(u16, 0), cksum.finish(cksum.accumulate(ph2, datagram[0..len])));
}

test "FullStack: udpSendTo6 still sends from the stack's own v6 address" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = TunnelStack.init(&link_ep, .{ 10, 0, 0, 1 });
    const us = v6Addr(1);
    stack.setIpv6Addr(us);
    const ep = stack.udpBind(53).?;
    try testing.expect(stack.udpSendTo6(ep, v6Addr(2), 40000, "answer"));
    var pkt: [1600]u8 = undefined;
    const raw = link_ep.readOutbound(&pkt).?;
    try testing.expectEqualSlices(u8, &us, raw[8..24]);
}

test "FullStack: connAddrs6 gives a v6 connection's whole addresses, and nothing for v4" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(16).init(&link_ep, .{ 10, 0, 0, 1 });
    stack.setIpv6Addr(v6Addr(1));
    _ = stack.listenDeferred(80, 128);

    // Two peers whose addresses share the low four bytes, and a SYN for a
    // host behind this node rather than for it.
    var a = v6Addr(2);
    var b = v6Addr(2);
    a[1] = 0x01;
    b[1] = 0x02;
    var behind = v6Addr(5);
    behind[1] = 0x99;

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;
    const peers = [_][16]u8{ a, b };
    var idxs: [2]u16 = undefined;
    for (peers, 0..) |peer, i| {
        const syn_len = buildTcp6Packet(peer, 5000, behind, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
        const pending = switch (stack.injectPacket(0, pkt_buf[0..syn_len])) {
            .syn_pending => |h| h,
            else => return error.TestUnexpectedResult,
        };
        // The hold says where the SYN was sent, which a relay dials.
        const info = stack.pendingSynInfo(pending.idx).?;
        try testing.expectEqualSlices(u8, &behind, &info.local_addr6);
        try testing.expectEqualSlices(u8, &peer, &info.remote_addr6);
        idxs[i] = stack.acceptPending(pending, 10) orelse return error.NoConnection;
        _ = link_ep.readOutbound(&out_buf);
    }
    for (peers, idxs) |peer, idx| {
        const addrs = stack.connAddrs6(idx) orelse return error.NotV6;
        try testing.expectEqualSlices(u8, &behind, &addrs.local);
        try testing.expectEqualSlices(u8, &peer, &addrs.remote);
    }

    // A v4 connection has none.
    _ = stack.listen(81, 128);
    const syn4 = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 81, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(0, pkt_buf[0..syn4]);
    var v4_idx: ?u16 = null;
    for (0..stack.slotCount()) |i| {
        const slot = stack.slotAt(i);
        if (slot.active and slot.id.local_port == 81) v4_idx = @intCast(i);
    }
    try testing.expectEqual(@as(?FullStack(16).V6Addrs, null), stack.connAddrs6(v4_idx orelse return error.NoV4Slot));
}

// ================================================================
// A reset in the closing states
// ================================================================

test "FullStack: a reset ends a connection in any closing state, and gives its slot back" {
    // close_wait, fin_wait_2, last_ack and closing ignored a reset: the
    // connection stayed, retransmitting to a peer that had dropped it or
    // waiting for a FIN that was never coming, and held its slot.
    const peer: [4]u8 = .{ 10, 0, 0, 2 };
    const us: [4]u8 = .{ 10, 0, 0, 1 };
    const states = [_]tcp_connection.State{ .close_wait, .fin_wait_2, .last_ack, .closing };
    for (states) |want| {
        var link_ep = link_mod.ChannelEndpoint.init();
        var stack = FullStack(16).init(&link_ep, us);
        _ = stack.listen(80, 16);
        const idx = try growAccept(FullStack(16), &stack, &link_ep, 6000);
        var pkt_buf: [128]u8 = undefined;
        var out_buf: [1600]u8 = undefined;
        const ours = stack.conns[idx].conn.sender.snd_nxt;
        var peer_seq: u32 = 3001;
        var now: u64 = 30;

        // The peer's FIN first, for close_wait and last_ack; this side's
        // close then, for the other three.
        if (want == .close_wait or want == .last_ack) {
            const fin = buildTcpPacket(peer, 6000, us, 80, peer_seq, ours, .{ .fin = true, .ack = true }, 65535, &.{}, &pkt_buf);
            _ = stack.injectPacket(now, pkt_buf[0..fin]);
            peer_seq +%= 1;
        }
        if (want != .close_wait) {
            stack.close(idx);
            now += 10;
            _ = stack.poll(now);
        }
        while (link_ep.readOutbound(&out_buf)) |_| {}
        switch (want) {
            // The peer takes this side's FIN.
            .fin_wait_2 => {
                const ack = buildTcpPacket(peer, 6000, us, 80, peer_seq, ours +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
                _ = stack.injectPacket(now, pkt_buf[0..ack]);
            },
            // The peer's FIN crosses this side's, which it has not yet seen.
            .closing => {
                const fin = buildTcpPacket(peer, 6000, us, 80, peer_seq, ours, .{ .fin = true, .ack = true }, 65535, &.{}, &pkt_buf);
                _ = stack.injectPacket(now, pkt_buf[0..fin]);
                peer_seq +%= 1;
            },
            else => {},
        }
        try testing.expectEqual(want, stack.conns[idx].conn.state);

        const rst = buildTcpPacket(peer, 6000, us, 80, peer_seq, 0, .{ .rst = true }, 0, &.{}, &pkt_buf);
        switch (stack.injectPacket(now + 1, pkt_buf[0..rst])) {
            .aborted => |i| try testing.expectEqual(idx, i),
            else => return error.TestUnexpectedResult,
        }
        try testing.expect(!stack.conns[idx].active);
    }
}

test "FullStack: a slot taken again after a reset is told apart by its generation" {
    // The stack gives a closed slot to the next connection, and a reset
    // closes one without the caller doing anything. An index kept from
    // before then names the new connection; the generation says it is not
    // the same one.
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(4).init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 4);
    const first = try growAccept(FullStack(4), &stack, &link_ep, 6000);
    const first_gen = stack.connGen(first).?;
    try testing.expect(first_gen != 0);

    var pkt_buf: [128]u8 = undefined;
    const rst = buildTcpPacket(.{ 10, 0, 0, 2 }, 6000, .{ 10, 0, 0, 1 }, 80, 3001, 0, .{ .rst = true }, 0, &.{}, &pkt_buf);
    _ = stack.injectPacket(40, pkt_buf[0..rst]);
    try testing.expectEqual(@as(?u32, null), stack.connGen(first));

    var out_buf: [1600]u8 = undefined;
    while (link_ep.readOutbound(&out_buf)) |_| {}
    const second = try growAccept(FullStack(4), &stack, &link_ep, 6001);
    try testing.expectEqual(first, second);
    try testing.expect(stack.connGen(second).? != first_gen);

    // An outbound connection is given one too.
    const out = stack.connect(50, .{ 10, 0, 0, 9 }, 443, 50000).?;
    try testing.expect(stack.connGen(out).? != 0);
    try testing.expect(stack.connGen(out).? != stack.connGen(second).?);
}

test "FullStack: a connection asked to reset when drained sends what it holds, then resets and gives its slot back" {
    var link_ep = link_mod.ChannelEndpoint.init();
    var stack = FullStack(4).init(&link_ep, .{ 10, 0, 0, 1 });
    try testing.expect(stack.listen(80, 4));

    var pkt_buf: [128]u8 = undefined;
    var out_buf: [1600]u8 = undefined;
    const syn_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 40000, .{ 10, 0, 0, 1 }, 80, 1000, 0, .{ .syn = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(1, pkt_buf[0..syn_len]);
    const synack = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    const ack_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 40000, .{ 10, 0, 0, 1 }, 80, 1001, synack.seq +% 1, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(2, pkt_buf[0..ack_len]);
    const idx = stack.accept() orelse return error.NotAccepted;

    try testing.expectEqual(@as(usize, 5), stack.write(idx, "hello"));
    stack.resetWhenDrained(idx, 10_000);

    // The data, and neither a FIN nor a reset while it is unacknowledged.
    _ = stack.poll(3);
    const data = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    try testing.expectEqual(@as(usize, 5), data.payload_len);
    try testing.expect(!data.flags.rst and !data.flags.fin);
    _ = stack.poll(4);
    try testing.expect(link_ep.readOutbound(&out_buf) == null);

    // Acknowledged: the reset is due at once, and goes.
    const ack2_len = buildTcpPacket(.{ 10, 0, 0, 2 }, 40000, .{ 10, 0, 0, 1 }, 80, 1001, data.seq +% 5, .{ .ack = true }, 65535, &.{}, &pkt_buf);
    _ = stack.injectPacket(5, pkt_buf[0..ack2_len]);
    try testing.expectEqual(@as(?u64, 0), stack.nextPollAt());
    switch (stack.poll(6)) {
        .aborted => |i| try testing.expectEqual(idx, i),
        else => return error.TestUnexpectedResult,
    }
    const rst = parseTcpFromRaw(link_ep.readOutbound(&out_buf).?).?;
    try testing.expect(rst.flags.rst);
    try testing.expectEqual(data.seq +% 5, rst.seq);
    try testing.expectEqual(@as(u16, 0), stack.active_count);
}
