// Transport Demultiplexer: routes inbound packets to the correct endpoint
// based on 4-tuple (src_addr, src_port, dst_addr, dst_port) or 2-tuple (dst_port).
//
// Design: fixed-capacity hash map, no heap allocation on the data path.

const std = @import("std");

/// 4-tuple identifying a connection.
pub const FourTuple = struct {
    src_addr: [16]u8, // IPv6-sized (IPv4 mapped into last 4 bytes)
    dst_addr: [16]u8,
    src_port: u16,
    dst_port: u16,
    protocol: u8, // 6=TCP, 17=UDP

    pub fn hash(self: FourTuple) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(&self.src_addr);
        h.update(&self.dst_addr);
        h.update(std.mem.asBytes(&self.src_port));
        h.update(std.mem.asBytes(&self.dst_port));
        h.update(std.mem.asBytes(&self.protocol));
        return h.final();
    }

    pub fn eql(a: FourTuple, b: FourTuple) bool {
        return std.mem.eql(u8, &a.src_addr, &b.src_addr) and
            std.mem.eql(u8, &a.dst_addr, &b.dst_addr) and
            a.src_port == b.src_port and
            a.dst_port == b.dst_port and
            a.protocol == b.protocol;
    }
};

/// 2-tuple for listening sockets (protocol + local port).
pub const ListenKey = struct {
    port: u16,
    protocol: u8,

    pub fn hash(self: ListenKey) u64 {
        var h = std.hash.Wyhash.init(0x1234);
        h.update(std.mem.asBytes(&self.port));
        h.update(std.mem.asBytes(&self.protocol));
        return h.final();
    }

    pub fn eql(a: ListenKey, b: ListenKey) bool {
        return a.port == b.port and a.protocol == b.protocol;
    }
};

/// Endpoint ID (opaque handle for the endpoint that should receive packets).
pub const EndpointId = u16;

/// Demuxer with fixed capacity.
pub fn Demuxer(comptime max_connected: usize, comptime max_listeners: usize) type {
    return struct {
        const Self = @This();

        /// Connected sockets: 4-tuple → endpoint.
        connected_keys: [max_connected]FourTuple = undefined,
        connected_vals: [max_connected]EndpointId = undefined,
        connected_used: [max_connected]bool = [_]bool{false} ** max_connected,
        connected_count: usize = 0,

        /// Listening sockets: 2-tuple → endpoint.
        listener_keys: [max_listeners]ListenKey = undefined,
        listener_vals: [max_listeners]EndpointId = undefined,
        listener_used: [max_listeners]bool = [_]bool{false} ** max_listeners,
        listener_count: usize = 0,

        pub fn init() Self {
            return .{};
        }

        /// Register a connected endpoint (4-tuple match).
        pub fn registerConnected(self: *Self, key: FourTuple, ep_id: EndpointId) bool {
            if (self.connected_count >= max_connected) return false;
            // Find empty slot (linear probe)
            const start = key.hash() % max_connected;
            var i = start;
            while (true) {
                if (!self.connected_used[i]) {
                    self.connected_keys[i] = key;
                    self.connected_vals[i] = ep_id;
                    self.connected_used[i] = true;
                    self.connected_count += 1;
                    return true;
                }
                i = (i + 1) % max_connected;
                if (i == start) return false;
            }
        }

        /// Unregister a connected endpoint.
        pub fn unregisterConnected(self: *Self, key: FourTuple) bool {
            const start = key.hash() % max_connected;
            var i = start;
            while (true) {
                if (self.connected_used[i] and self.connected_keys[i].eql(key)) {
                    self.connected_used[i] = false;
                    self.connected_count -= 1;
                    return true;
                }
                if (!self.connected_used[i]) return false;
                i = (i + 1) % max_connected;
                if (i == start) return false;
            }
        }

        /// Register a listening endpoint (2-tuple match).
        pub fn registerListener(self: *Self, key: ListenKey, ep_id: EndpointId) bool {
            if (self.listener_count >= max_listeners) return false;
            const start = key.hash() % max_listeners;
            var i = start;
            while (true) {
                if (!self.listener_used[i]) {
                    self.listener_keys[i] = key;
                    self.listener_vals[i] = ep_id;
                    self.listener_used[i] = true;
                    self.listener_count += 1;
                    return true;
                }
                i = (i + 1) % max_listeners;
                if (i == start) return false;
            }
        }

        /// Unregister a listener.
        pub fn unregisterListener(self: *Self, key: ListenKey) bool {
            const start = key.hash() % max_listeners;
            var i = start;
            while (true) {
                if (self.listener_used[i] and self.listener_keys[i].eql(key)) {
                    self.listener_used[i] = false;
                    self.listener_count -= 1;
                    return true;
                }
                if (!self.listener_used[i]) return false;
                i = (i + 1) % max_listeners;
                if (i == start) return false;
            }
        }

        /// Look up endpoint for a packet. First tries 4-tuple, then 2-tuple (listener).
        pub fn lookup(self: *const Self, tuple: FourTuple) ?EndpointId {
            // Try connected (4-tuple exact match)
            const c_start = tuple.hash() % max_connected;
            var i = c_start;
            while (true) {
                if (self.connected_used[i] and self.connected_keys[i].eql(tuple)) {
                    return self.connected_vals[i];
                }
                if (!self.connected_used[i]) break;
                i = (i + 1) % max_connected;
                if (i == c_start) break;
            }

            // Try listener (protocol + dst_port only)
            const listen_key = ListenKey{ .port = tuple.dst_port, .protocol = tuple.protocol };
            const l_start = listen_key.hash() % max_listeners;
            var j = l_start;
            while (true) {
                if (self.listener_used[j] and self.listener_keys[j].eql(listen_key)) {
                    return self.listener_vals[j];
                }
                if (!self.listener_used[j]) break;
                j = (j + 1) % max_listeners;
                if (j == l_start) break;
            }

            return null;
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn makeIpv4Tuple(src: [4]u8, src_port: u16, dst: [4]u8, dst_port: u16, proto: u8) FourTuple {
    var t: FourTuple = .{
        .src_addr = [_]u8{0} ** 16,
        .dst_addr = [_]u8{0} ** 16,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = proto,
    };
    @memcpy(t.src_addr[12..16], &src);
    @memcpy(t.dst_addr[12..16], &dst);
    return t;
}

test "Demuxer: connected lookup" {
    var dmx = Demuxer(16, 4).init();

    const key = makeIpv4Tuple(.{ 10, 0, 0, 1 }, 12345, .{ 10, 0, 0, 2 }, 80, 6);
    try testing.expect(dmx.registerConnected(key, 1));

    try testing.expectEqual(@as(?EndpointId, 1), dmx.lookup(key));

    // Different tuple should miss
    const other = makeIpv4Tuple(.{ 10, 0, 0, 3 }, 54321, .{ 10, 0, 0, 2 }, 80, 6);
    try testing.expectEqual(@as(?EndpointId, null), dmx.lookup(other));
}

test "Demuxer: listener fallback" {
    var dmx = Demuxer(16, 4).init();

    // Register a listener on port 53, UDP
    try testing.expect(dmx.registerListener(.{ .port = 53, .protocol = 17 }, 42));

    // Any packet to port 53 UDP should match
    const pkt = makeIpv4Tuple(.{ 10, 0, 0, 1 }, 1234, .{ 10, 0, 0, 2 }, 53, 17);
    try testing.expectEqual(@as(?EndpointId, 42), dmx.lookup(pkt));
}

test "Demuxer: connected takes priority over listener" {
    var dmx = Demuxer(16, 4).init();

    const key = makeIpv4Tuple(.{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 80, 6);
    try testing.expect(dmx.registerListener(.{ .port = 80, .protocol = 6 }, 100));
    try testing.expect(dmx.registerConnected(key, 200));

    // Connected match wins
    try testing.expectEqual(@as(?EndpointId, 200), dmx.lookup(key));

    // Different src goes to listener
    const other = makeIpv4Tuple(.{ 10, 0, 0, 3 }, 6000, .{ 10, 0, 0, 2 }, 80, 6);
    try testing.expectEqual(@as(?EndpointId, 100), dmx.lookup(other));
}

test "Demuxer: unregister" {
    var dmx = Demuxer(16, 4).init();

    const key = makeIpv4Tuple(.{ 10, 0, 0, 1 }, 1000, .{ 10, 0, 0, 2 }, 2000, 6);
    try testing.expect(dmx.registerConnected(key, 5));
    try testing.expectEqual(@as(?EndpointId, 5), dmx.lookup(key));

    try testing.expect(dmx.unregisterConnected(key));
    try testing.expectEqual(@as(?EndpointId, null), dmx.lookup(key));
}
