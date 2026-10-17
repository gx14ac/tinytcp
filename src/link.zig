// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

// LinkEndpoint: comptime interface for injecting/extracting raw IP packets.
//
// Implementations:
// - channel.zig: in-memory test endpoint
// - wireguard.zig: WireGuard tunnel integration (future)

const PacketBuf = @import("packet_buf.zig").PacketBuf;

/// Comptime interface that any link endpoint must satisfy.
/// Implementations provide inject (receive from wire) and extract (send to wire).
pub fn LinkEndpoint(comptime Self: type) type {
    return struct {
        /// Inject a received packet (from wire → stack).
        /// The packet data is in pkt.data(). Returns true if accepted.
        pub const inject = @field(Self, "inject");

        /// Extract a packet to send (stack → wire).
        /// Called by the stack when it has an outbound packet ready.
        pub const extract = @field(Self, "extract");
    };
}

/// Parameterized in-memory channel endpoint for testing.
pub fn ChannelEndpointWith(comptime queue_size: usize, comptime mtu: usize) type {
    return ChannelEndpointSized(queue_size, queue_size, mtu);
}

/// The same, with a queue size for each way. A user that injects packets
/// into the stack directly and only ever reads the outbound side needs
/// room there for a burst — every connection's reply in one poll — and
/// next to none inbound; equal sizes would spend as much again on a queue
/// nothing fills.
pub fn ChannelEndpointSized(comptime out_queue_size: usize, comptime in_queue_size: usize, comptime mtu: usize) type {
    return struct {
        const Self = @This();
        const max_queue: usize = out_queue_size;
        const max_in_queue: usize = in_queue_size;
        const max_pkt: usize = mtu;

        out_bufs: [max_queue][max_pkt]u8 = undefined,
        out_lens: [max_queue]u16 = [_]u16{0} ** max_queue,
        out_head: usize = 0,
        out_tail: usize = 0,
        out_count: usize = 0,

        /// Packets refused because the queue was full, each way. Nothing
        /// else says a packet was lost here: the stack's sends ignore the
        /// answer, and a TCP segment dropped at this point is only seen as
        /// the far end's retransmission, seconds later.
        out_dropped: u64 = 0,
        in_dropped: u64 = 0,
        /// Packets refused for being larger than the endpoint's MTU, each
        /// way. Apart from the above: a queue too small and a packet too
        /// big are different mistakes with the same symptom.
        out_oversize: u64 = 0,
        in_oversize: u64 = 0,
        /// The last outbound packet refused for its size: how large, and
        /// the IP protocol in it (0 when it was not IPv4). What says which
        /// part of the stack built something the link cannot take.
        out_oversize_len: usize = 0,
        out_oversize_proto: u8 = 0,

        in_bufs: [max_in_queue][max_pkt]u8 = undefined,
        in_lens: [max_in_queue]u16 = [_]u16{0} ** max_in_queue,
        in_head: usize = 0,
        in_tail: usize = 0,
        in_count: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn extract(self: *Self, pkt: *const PacketBuf) bool {
            const data = pkt.data();
            if (data.len > max_pkt) {
                self.noteOversize(data);
                return false;
            }
            if (self.out_count >= max_queue) {
                self.out_dropped += 1;
                return false;
            }
            @memcpy(self.out_bufs[self.out_tail][0..data.len], data);
            self.out_lens[self.out_tail] = @intCast(data.len);
            self.out_tail = (self.out_tail + 1) % max_queue;
            self.out_count += 1;
            return true;
        }

        pub fn writeInbound(self: *Self, data: []const u8) bool {
            if (data.len > max_pkt) {
                self.in_oversize += 1;
                return false;
            }
            if (self.in_count >= max_in_queue) {
                self.in_dropped += 1;
                return false;
            }
            @memcpy(self.in_bufs[self.in_tail][0..data.len], data);
            self.in_lens[self.in_tail] = @intCast(data.len);
            self.in_tail = (self.in_tail + 1) % max_in_queue;
            self.in_count += 1;
            return true;
        }

        pub fn inject(self: *Self, out_buf: []u8) ?[]const u8 {
            if (self.in_count == 0) return null;
            const pkt_len = self.in_lens[self.in_head];
            if (pkt_len > out_buf.len) return null;
            @memcpy(out_buf[0..pkt_len], self.in_bufs[self.in_head][0..pkt_len]);
            self.in_head = (self.in_head + 1) % max_in_queue;
            self.in_count -= 1;
            return out_buf[0..pkt_len];
        }

        pub fn writeOutbound(self: *Self, data: []const u8) void {
            if (data.len > max_pkt) {
                self.noteOversize(data);
                return;
            }
            if (self.out_count >= max_queue) {
                self.out_dropped += 1;
                return;
            }
            @memcpy(self.out_bufs[self.out_tail][0..data.len], data);
            self.out_lens[self.out_tail] = @intCast(data.len);
            self.out_tail = (self.out_tail + 1) % max_queue;
            self.out_count += 1;
        }

        pub fn readOutbound(self: *Self, out_buf: []u8) ?[]const u8 {
            if (self.out_count == 0) return null;
            const pkt_len = self.out_lens[self.out_head];
            if (pkt_len > out_buf.len) return null;
            @memcpy(out_buf[0..pkt_len], self.out_bufs[self.out_head][0..pkt_len]);
            self.out_head = (self.out_head + 1) % max_queue;
            self.out_count -= 1;
            return out_buf[0..pkt_len];
        }

        pub fn outboundCount(self: *const Self) usize {
            return self.out_count;
        }

        pub fn inboundCount(self: *const Self) usize {
            return self.in_count;
        }

        /// How many outbound packets were refused for a full queue, since
        /// the start.
        pub fn outboundDropped(self: *const Self) u64 {
            return self.out_dropped;
        }

        fn noteOversize(self: *Self, data: []const u8) void {
            self.out_oversize += 1;
            self.out_oversize_len = data.len;
            self.out_oversize_proto = if (data.len >= 20 and data[0] >> 4 == 4) data[9] else 0;
        }

        /// How many outbound packets were refused for being too large.
        pub fn outboundOversize(self: *const Self) u64 {
            return self.out_oversize;
        }

        /// How many inbound packets were refused for a full queue.
        pub fn inboundDropped(self: *const Self) u64 {
            return self.in_dropped;
        }

        /// How many inbound packets were refused for being too large.
        pub fn inboundOversize(self: *const Self) u64 {
            return self.in_oversize;
        }
    };
}

/// Default in-memory channel endpoint for testing.
pub const ChannelEndpoint = ChannelEndpointWith(64, 1600);

// ============================================================================
// Tests
// ============================================================================

const testing = @import("std").testing;

test "ChannelEndpoint: basic inject and extract" {
    var ep = ChannelEndpoint.init();

    // Simulate receiving from wire
    const pkt_data = [_]u8{ 0x45, 0x00, 0x00, 0x14 } ++ [_]u8{0} ** 16;
    try testing.expect(ep.writeInbound(&pkt_data));
    try testing.expectEqual(@as(usize, 1), ep.inboundCount());

    // Stack reads inbound
    var buf: [1600]u8 = undefined;
    const received = ep.inject(&buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(usize, 20), received.len);
    try testing.expectEqual(@as(usize, 0), ep.inboundCount());
}

test "ChannelEndpoint: extract and readOutbound" {
    var ep = ChannelEndpoint.init();

    // Stack sends a packet
    var backing: [256]u8 = undefined;
    var pb = PacketBuf.init(&backing, 64);
    const payload = "hello";
    @memcpy((try pb.append(payload.len))[0..payload.len], payload);

    try testing.expect(ep.extract(&pb));
    try testing.expectEqual(@as(usize, 1), ep.outboundCount());

    // Test code reads what was sent
    var out_buf: [1600]u8 = undefined;
    const sent = ep.readOutbound(&out_buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "hello", sent);
}

test "ChannelEndpoint: a full queue counts what it refuses, both ways" {
    const Small = ChannelEndpointWith(2, 64);
    var ep = Small.init();
    var backing: [128]u8 = undefined;
    var pb = PacketBuf.init(&backing, 16);
    @memcpy((try pb.append(4))[0..4], "abcd");

    try testing.expect(ep.extract(&pb));
    try testing.expect(ep.extract(&pb));
    try testing.expectEqual(@as(u64, 0), ep.outboundDropped());
    try testing.expect(!ep.extract(&pb));
    ep.writeOutbound("efgh");
    try testing.expectEqual(@as(u64, 2), ep.outboundDropped());

    try testing.expect(ep.writeInbound("ijkl"));
    try testing.expect(ep.writeInbound("mnop"));
    try testing.expect(!ep.writeInbound("qrst"));
    try testing.expectEqual(@as(u64, 1), ep.inboundDropped());
    // Too big is refused too, and counted apart.
    const big = [_]u8{0} ** 65;
    try testing.expect(!ep.writeInbound(&big));
    try testing.expectEqual(@as(u64, 1), ep.inboundDropped());
    try testing.expectEqual(@as(u64, 1), ep.inboundOversize());
    ep.writeOutbound(&big);
    try testing.expectEqual(@as(u64, 2), ep.outboundDropped());
    try testing.expectEqual(@as(u64, 1), ep.outboundOversize());
}

test "ChannelEndpointSized: each way holds its own number" {
    const Lopsided = ChannelEndpointSized(3, 1, 64);
    var ep = Lopsided.init();
    var backing: [128]u8 = undefined;
    var pb = PacketBuf.init(&backing, 16);
    @memcpy((try pb.append(4))[0..4], "abcd");
    for (0..3) |_| try testing.expect(ep.extract(&pb));
    try testing.expect(!ep.extract(&pb));
    try testing.expect(ep.writeInbound("x"));
    try testing.expect(!ep.writeInbound("y"));
    // Round and round, inbound, with a queue of one.
    var out: [64]u8 = undefined;
    for (0..5) |_| {
        _ = ep.inject(&out) orelse return error.Empty;
        try testing.expect(ep.writeInbound("z"));
    }
    try testing.expect(@sizeOf(Lopsided) < @sizeOf(ChannelEndpointWith(3, 64)));
}
