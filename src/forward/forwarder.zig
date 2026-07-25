// Forwarder: L4 packet forwarding engine.
//
// Routes packets between the WireGuard tunnel (virtual addresses)
// and local endpoints. Implements:
// - DNAT/SNAT for outbound connections
// - Port mapping for inbound connections
// - Flow tracking with idle expiry
// - TCP connection proxying via tinytcp Connection
//
// Sans-IO: produces forwarding decisions; caller performs actual I/O.

const std = @import("std");
const flow_table_mod = @import("flow_table.zig");

const FlowKey = flow_table_mod.FlowKey;
const FlowEntry = flow_table_mod.FlowEntry;

/// Forwarding decision.
pub const Decision = union(enum) {
    /// Forward the packet (possibly with NAT rewrite).
    forward: ForwardInfo,
    /// Drop the packet.
    drop: DropReason,
    /// Deliver to local stack (packet is for us).
    local,
    /// Generate ICMP unreachable.
    icmp_unreachable,
};

pub const ForwardInfo = struct {
    /// New source address (after SNAT). null = no rewrite.
    new_src_addr: ?[4]u8 = null,
    /// New source port (after SNAT). null = no rewrite.
    new_src_port: ?u16 = null,
    /// New destination address (after DNAT). null = no rewrite.
    new_dst_addr: ?[4]u8 = null,
    /// New destination port (after DNAT). null = no rewrite.
    new_dst_port: ?u16 = null,
    /// Decrement TTL.
    decrement_ttl: bool = true,
};

pub const DropReason = enum {
    /// TTL expired.
    ttl_expired,
    /// No route to destination.
    no_route,
    /// Blocked by ACL.
    acl_blocked,
    /// Flow table full.
    table_full,
    /// Invalid packet.
    invalid,
};

/// Forwarder configuration.
pub const Config = struct {
    /// Local tunnel address (WonderIP).
    local_addr: [4]u8 = .{ 100, 64, 0, 1 },
    /// Subnet for the mesh (e.g., 100.64.0.0/10).
    mesh_prefix: [4]u8 = .{ 100, 64, 0, 0 },
    mesh_prefix_len: u8 = 10,
    /// Enable exit node mode (forward to internet).
    exit_node: bool = false,
    /// NAT pool start port.
    nat_port_start: u16 = 32768,
    /// NAT pool end port.
    nat_port_end: u16 = 61000,
};

/// The Forwarder.
pub fn Forwarder(comptime max_flows: usize) type {
    return struct {
        const Self = @This();

        flows: flow_table_mod.FlowTable(max_flows),
        config: Config,
        /// Next NAT port to allocate (round-robin).
        next_nat_port: u16,

        pub fn init(config: Config) Self {
            return Self{
                .flows = flow_table_mod.FlowTable(max_flows).init(),
                .config = config,
                .next_nat_port = config.nat_port_start,
            };
        }

        /// Decide what to do with an inbound packet (from tunnel).
        pub fn decideInbound(self: *Self, now_ms: u64, src_addr: [4]u8, src_port: u16, dst_addr: [4]u8, dst_port: u16, protocol: u8, ttl: u8) Decision {
            // TTL check
            if (ttl == 0) return .{ .drop = .ttl_expired };

            // Is it for us?
            if (std.mem.eql(u8, &dst_addr, &self.config.local_addr)) {
                return .local;
            }

            // Is it within the mesh?
            if (self.isInMesh(dst_addr)) {
                // Direct mesh forwarding (no NAT needed)
                const key = FlowKey.fromIpv4(src_addr, src_port, dst_addr, dst_port, protocol);
                self.flows.touch(&key, now_ms);
                return .{ .forward = .{ .decrement_ttl = true } };
            }

            // Exit node check
            if (!self.config.exit_node) {
                return .{ .drop = .no_route };
            }

            // Outbound to internet: apply SNAT
            const key = FlowKey.fromIpv4(src_addr, src_port, dst_addr, dst_port, protocol);

            // Check existing flow
            if (self.flows.lookup(&key)) |entry| {
                entry.last_active_ms = now_ms;
                return .{ .forward = .{
                    .new_src_addr = self.config.local_addr,
                    .new_src_port = entry.nat_port,
                    .decrement_ttl = true,
                } };
            }

            // Create new flow with NAT port
            const entry = self.flows.insert(key, now_ms) orelse {
                return .{ .drop = .table_full };
            };
            entry.nat_port = self.allocNatPort();

            return .{ .forward = .{
                .new_src_addr = self.config.local_addr,
                .new_src_port = entry.nat_port,
                .decrement_ttl = true,
            } };
        }

        /// Decide what to do with a packet coming from the internet (for exit node).
        pub fn decideOutbound(self: *Self, now_ms: u64, src_addr: [4]u8, src_port: u16, dst_addr: [4]u8, dst_port: u16, protocol: u8) Decision {
            // Reverse lookup: the packet arrives at our NAT port
            // Find the original flow
            const rev_key = FlowKey.fromIpv4(src_addr, src_port, dst_addr, dst_port, protocol);

            // Search for a flow where nat_port matches dst_port
            // In a real impl we'd have a reverse NAT table; here we do reverse lookup
            const fwd_key = self.findByNatPort(dst_port, protocol, src_addr, src_port);
            if (fwd_key) |key| {
                self.flows.touch(key, now_ms);
                // DNAT: rewrite dst to original source
                var orig_src: [4]u8 = undefined;
                @memcpy(&orig_src, key.src_addr[12..16]);
                return .{ .forward = .{
                    .new_dst_addr = orig_src,
                    .new_dst_port = key.src_port,
                    .decrement_ttl = true,
                } };
            }

            _ = rev_key;
            return .{ .drop = .no_route };
        }

        /// Expire idle flows.
        pub fn tick(self: *Self, now_ms: u64) usize {
            return self.flows.expireIdle(now_ms);
        }

        /// Check if an address is in the mesh subnet.
        fn isInMesh(self: *const Self, addr: [4]u8) bool {
            const prefix_bits = self.config.mesh_prefix_len;
            const mask = if (prefix_bits >= 32) @as(u32, 0xFFFFFFFF) else (@as(u32, 0xFFFFFFFF) << @intCast(32 - prefix_bits));
            const addr_u32 = std.mem.readInt(u32, &addr, .big);
            const prefix_u32 = std.mem.readInt(u32, &self.config.mesh_prefix, .big);
            return (addr_u32 & mask) == (prefix_u32 & mask);
        }

        /// Allocate a NAT port (round-robin).
        fn allocNatPort(self: *Self) u16 {
            const port = self.next_nat_port;
            self.next_nat_port += 1;
            if (self.next_nat_port >= self.config.nat_port_end) {
                self.next_nat_port = self.config.nat_port_start;
            }
            return port;
        }

        /// Find a flow entry by NAT port (reverse lookup for DNAT).
        fn findByNatPort(self: *Self, nat_port: u16, protocol: u8, remote_addr: [4]u8, remote_port: u16) ?*const FlowKey {
            for (&self.flows.entries) |*entry| {
                if (!entry.occupied) continue;
                if (entry.nat_port == nat_port and entry.key.protocol == protocol) {
                    // Verify remote matches
                    if (entry.key.dst_port == remote_port and
                        std.mem.eql(u8, entry.key.dst_addr[12..16], &remote_addr))
                    {
                        return &entry.key;
                    }
                }
            }
            return null;
        }
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Forwarder: local delivery" {
    var fwd = Forwarder(256).init(.{
        .local_addr = .{ 100, 64, 0, 1 },
        .mesh_prefix = .{ 100, 64, 0, 0 },
        .mesh_prefix_len = 10,
    });

    const decision = fwd.decideInbound(
        100,
        .{ 100, 64, 0, 2 },
        5000,
        .{ 100, 64, 0, 1 }, // our address
        80,
        6,
        64,
    );
    switch (decision) {
        .local => {},
        else => return error.TestUnexpectedResult,
    }
}

test "Forwarder: mesh forwarding" {
    var fwd = Forwarder(256).init(.{
        .local_addr = .{ 100, 64, 0, 1 },
        .mesh_prefix = .{ 100, 64, 0, 0 },
        .mesh_prefix_len = 10,
    });

    const decision = fwd.decideInbound(
        100,
        .{ 100, 64, 0, 2 },
        5000,
        .{ 100, 64, 0, 3 }, // another mesh address
        80,
        6,
        64,
    );
    switch (decision) {
        .forward => |info| {
            try testing.expect(info.new_src_addr == null); // no NAT
            try testing.expect(info.decrement_ttl);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "Forwarder: exit node SNAT" {
    var fwd = Forwarder(256).init(.{
        .local_addr = .{ 100, 64, 0, 1 },
        .mesh_prefix = .{ 100, 64, 0, 0 },
        .mesh_prefix_len = 10,
        .exit_node = true,
        .nat_port_start = 40000,
        .nat_port_end = 50000,
    });

    const decision = fwd.decideInbound(
        100,
        .{ 100, 64, 0, 2 },
        5000,
        .{ 8, 8, 8, 8 }, // internet address
        443,
        6,
        64,
    );
    switch (decision) {
        .forward => |info| {
            try testing.expect(info.new_src_addr != null);
            try testing.expectEqualSlices(u8, &[_]u8{ 100, 64, 0, 1 }, &info.new_src_addr.?);
            try testing.expect(info.new_src_port != null);
            try testing.expectEqual(@as(u16, 40000), info.new_src_port.?);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "Forwarder: no exit node drops internet traffic" {
    var fwd = Forwarder(256).init(.{
        .local_addr = .{ 100, 64, 0, 1 },
        .mesh_prefix = .{ 100, 64, 0, 0 },
        .mesh_prefix_len = 10,
        .exit_node = false,
    });

    const decision = fwd.decideInbound(
        100,
        .{ 100, 64, 0, 2 },
        5000,
        .{ 8, 8, 8, 8 }, // internet
        443,
        6,
        64,
    );
    switch (decision) {
        .drop => |reason| try testing.expectEqual(DropReason.no_route, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "Forwarder: TTL expired" {
    var fwd = Forwarder(256).init(.{});

    const decision = fwd.decideInbound(100, .{ 10, 0, 0, 1 }, 5000, .{ 10, 0, 0, 2 }, 80, 6, 0);
    switch (decision) {
        .drop => |reason| try testing.expectEqual(DropReason.ttl_expired, reason),
        else => return error.TestUnexpectedResult,
    }
}
