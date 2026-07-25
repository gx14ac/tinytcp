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
    return struct {
        const Self = @This();
        const max_queue: usize = queue_size;
        const max_pkt: usize = mtu;

        out_bufs: [max_queue][max_pkt]u8 = undefined,
        out_lens: [max_queue]u16 = [_]u16{0} ** max_queue,
        out_head: usize = 0,
        out_tail: usize = 0,
        out_count: usize = 0,

        in_bufs: [max_queue][max_pkt]u8 = undefined,
        in_lens: [max_queue]u16 = [_]u16{0} ** max_queue,
        in_head: usize = 0,
        in_tail: usize = 0,
        in_count: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn extract(self: *Self, pkt: *const PacketBuf) bool {
            if (self.out_count >= max_queue) return false;
            const data = pkt.data();
            if (data.len > max_pkt) return false;
            @memcpy(self.out_bufs[self.out_tail][0..data.len], data);
            self.out_lens[self.out_tail] = @intCast(data.len);
            self.out_tail = (self.out_tail + 1) % max_queue;
            self.out_count += 1;
            return true;
        }

        pub fn writeInbound(self: *Self, data: []const u8) bool {
            if (self.in_count >= max_queue or data.len > max_pkt) return false;
            @memcpy(self.in_bufs[self.in_tail][0..data.len], data);
            self.in_lens[self.in_tail] = @intCast(data.len);
            self.in_tail = (self.in_tail + 1) % max_queue;
            self.in_count += 1;
            return true;
        }

        pub fn inject(self: *Self, out_buf: []u8) ?[]const u8 {
            if (self.in_count == 0) return null;
            const pkt_len = self.in_lens[self.in_head];
            if (pkt_len > out_buf.len) return null;
            @memcpy(out_buf[0..pkt_len], self.in_bufs[self.in_head][0..pkt_len]);
            self.in_head = (self.in_head + 1) % max_queue;
            self.in_count -= 1;
            return out_buf[0..pkt_len];
        }

        pub fn writeOutbound(self: *Self, data: []const u8) void {
            if (self.out_count >= max_queue or data.len > max_pkt) return;
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
