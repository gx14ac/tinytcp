// Route table: longest-prefix match routing for IP forwarding.
//
// Sans-IO, fixed capacity (comptime), supports IPv4 and IPv6.

const std = @import("std");

pub const Prefix = struct {
    addr: [16]u8 = [_]u8{0} ** 16,
    prefix_len: u8 = 0,
    is_v4: bool = false,

    pub fn fromIpv4(addr: [4]u8, prefix_len: u8) Prefix {
        var p = Prefix{ .prefix_len = prefix_len, .is_v4 = true };
        @memcpy(p.addr[0..4], &addr);
        return p;
    }

    pub fn fromIpv6(addr: [16]u8, prefix_len: u8) Prefix {
        return Prefix{ .addr = addr, .prefix_len = prefix_len, .is_v4 = false };
    }

    pub fn contains(self: *const Prefix, ip: [16]u8) bool {
        return self.matchBytes(&ip);
    }

    pub fn containsIpv4(self: *const Prefix, ip: [4]u8) bool {
        var buf: [16]u8 = [_]u8{0} ** 16;
        @memcpy(buf[0..4], &ip);
        return self.matchBytes(&buf);
    }

    fn matchBytes(self: *const Prefix, ip: []const u8) bool {
        if (self.prefix_len == 0) return true;
        const full_bytes = self.prefix_len / 8;
        const rem_bits: u4 = @intCast(self.prefix_len % 8);

        if (full_bytes > 0) {
            if (!std.mem.eql(u8, self.addr[0..full_bytes], ip[0..full_bytes])) return false;
        }
        if (rem_bits > 0) {
            const shift: u3 = @intCast(8 - rem_bits);
            const mask: u8 = @as(u8, 0xFF) << shift;
            if ((self.addr[full_bytes] & mask) != (ip[full_bytes] & mask)) return false;
        }
        return true;
    }
};

pub const Route = struct {
    destination: Prefix = .{},
    gateway: ?[16]u8 = null,
    metric: u16 = 0,
    nic_id: u8 = 0,
    active: bool = false,
};

pub fn RouteTable(comptime max_routes: usize) type {
    return struct {
        const Self = @This();

        routes: [max_routes]Route = [_]Route{.{}} ** max_routes,
        count: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn addRoute(self: *Self, destination: Prefix, gateway: ?[16]u8, metric: u16, nic_id: u8) bool {
            if (self.count >= max_routes) return false;
            for (&self.routes) |*r| {
                if (!r.active) {
                    r.* = Route{
                        .destination = destination,
                        .gateway = gateway,
                        .metric = metric,
                        .nic_id = nic_id,
                        .active = true,
                    };
                    self.count += 1;
                    return true;
                }
            }
            return false;
        }

        pub fn removeRoute(self: *Self, destination: Prefix) bool {
            for (&self.routes) |*r| {
                if (r.active and r.destination.prefix_len == destination.prefix_len and
                    std.mem.eql(u8, &r.destination.addr, &destination.addr))
                {
                    r.active = false;
                    self.count -= 1;
                    return true;
                }
            }
            return false;
        }

        pub fn lookup(self: *const Self, dst: [16]u8) ?*const Route {
            var best: ?*const Route = null;
            var best_prefix: u8 = 0;
            var best_metric: u16 = std.math.maxInt(u16);

            for (&self.routes) |*r| {
                if (!r.active) continue;
                if (!r.destination.contains(dst)) continue;
                if (r.destination.prefix_len > best_prefix or
                    (r.destination.prefix_len == best_prefix and r.metric < best_metric))
                {
                    best = r;
                    best_prefix = r.destination.prefix_len;
                    best_metric = r.metric;
                }
            }
            return best;
        }

        pub fn lookupIpv4(self: *const Self, dst: [4]u8) ?*const Route {
            var buf: [16]u8 = [_]u8{0} ** 16;
            @memcpy(buf[0..4], &dst);
            return self.lookup(buf);
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Prefix: contains IPv4" {
    const p = Prefix.fromIpv4(.{ 10, 0, 0, 0 }, 8);
    try testing.expect(p.containsIpv4(.{ 10, 1, 2, 3 }));
    try testing.expect(p.containsIpv4(.{ 10, 255, 255, 255 }));
    try testing.expect(!p.containsIpv4(.{ 11, 0, 0, 0 }));
    try testing.expect(!p.containsIpv4(.{ 192, 168, 1, 1 }));
}

test "Prefix: default route matches all" {
    const p = Prefix.fromIpv4(.{ 0, 0, 0, 0 }, 0);
    try testing.expect(p.containsIpv4(.{ 1, 2, 3, 4 }));
    try testing.expect(p.containsIpv4(.{ 255, 255, 255, 255 }));
}

test "Prefix: /32 exact match" {
    const p = Prefix.fromIpv4(.{ 10, 0, 0, 1 }, 32);
    try testing.expect(p.containsIpv4(.{ 10, 0, 0, 1 }));
    try testing.expect(!p.containsIpv4(.{ 10, 0, 0, 2 }));
}

test "RouteTable: longest prefix match" {
    var rt = RouteTable(16).init();
    // Default route
    try testing.expect(rt.addRoute(Prefix.fromIpv4(.{ 0, 0, 0, 0 }, 0), null, 100, 0));
    // More specific route
    try testing.expect(rt.addRoute(Prefix.fromIpv4(.{ 10, 0, 0, 0 }, 8), null, 50, 1));

    // 10.x should match /8
    const r1 = rt.lookupIpv4(.{ 10, 1, 2, 3 }).?;
    try testing.expectEqual(@as(u8, 8), r1.destination.prefix_len);
    try testing.expectEqual(@as(u8, 1), r1.nic_id);

    // 192.x should match default
    const r2 = rt.lookupIpv4(.{ 192, 168, 1, 1 }).?;
    try testing.expectEqual(@as(u8, 0), r2.destination.prefix_len);
}

test "RouteTable: metric tiebreak" {
    var rt = RouteTable(16).init();
    try testing.expect(rt.addRoute(Prefix.fromIpv4(.{ 10, 0, 0, 0 }, 8), null, 200, 0));
    try testing.expect(rt.addRoute(Prefix.fromIpv4(.{ 10, 0, 0, 0 }, 8), null, 50, 1));

    const r = rt.lookupIpv4(.{ 10, 1, 2, 3 }).?;
    try testing.expectEqual(@as(u16, 50), r.metric);
    try testing.expectEqual(@as(u8, 1), r.nic_id);
}

test "RouteTable: remove and readd" {
    var rt = RouteTable(16).init();
    const prefix = Prefix.fromIpv4(.{ 10, 0, 0, 0 }, 8);
    try testing.expect(rt.addRoute(prefix, null, 0, 0));
    try testing.expectEqual(@as(usize, 1), rt.count);

    try testing.expect(rt.removeRoute(prefix));
    try testing.expectEqual(@as(usize, 0), rt.count);
    try testing.expect(rt.lookupIpv4(.{ 10, 1, 2, 3 }) == null);

    try testing.expect(rt.addRoute(prefix, null, 0, 0));
    try testing.expect(rt.lookupIpv4(.{ 10, 1, 2, 3 }) != null);
}

test "RouteTable: no match returns null" {
    var rt = RouteTable(16).init();
    try testing.expect(rt.addRoute(Prefix.fromIpv4(.{ 10, 0, 0, 0 }, 8), null, 0, 0));
    try testing.expect(rt.lookupIpv4(.{ 192, 168, 1, 1 }) == null);
}

test "RouteTable: full table" {
    var rt = RouteTable(2).init();
    try testing.expect(rt.addRoute(Prefix.fromIpv4(.{ 10, 0, 0, 0 }, 8), null, 0, 0));
    try testing.expect(rt.addRoute(Prefix.fromIpv4(.{ 172, 16, 0, 0 }, 12), null, 0, 0));
    try testing.expect(!rt.addRoute(Prefix.fromIpv4(.{ 192, 168, 0, 0 }, 16), null, 0, 0));
}
