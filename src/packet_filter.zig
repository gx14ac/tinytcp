// Packet Filter / Firewall Rules (stateless).
//
// Simple rule-based packet filter supporting:
// - Source/destination IP matching (with prefix)
// - Source/destination port matching (with ranges)
// - Protocol matching (TCP, UDP, ICMP)
// - Allow/deny actions
// - Rule priority (first match wins)
//
// Sans-IO: purely evaluates rules against packet metadata.

const std = @import("std");
const route_mod = @import("route.zig");

/// Maximum number of filter rules.
const max_rules: usize = 64;

/// Filter action.
pub const Action = enum {
    allow,
    deny,
};

/// Protocol matcher.
pub const ProtoMatch = enum {
    any,
    tcp,
    udp,
    icmp,
};

/// Port range.
pub const PortRange = struct {
    min: u16 = 0,
    max: u16 = 65535,

    pub fn matches(self: PortRange, port: u16) bool {
        return port >= self.min and port <= self.max;
    }

    pub fn exact(port: u16) PortRange {
        return .{ .min = port, .max = port };
    }

    pub fn any() PortRange {
        return .{ .min = 0, .max = 65535 };
    }
};

/// A single filter rule.
pub const Rule = struct {
    active: bool = false,
    action: Action = .deny,
    direction: Direction = .inbound,

    // Matchers (all must match for rule to apply)
    src_prefix: ?route_mod.Prefix = null,
    dst_prefix: ?route_mod.Prefix = null,
    src_port: PortRange = PortRange.any(),
    dst_port: PortRange = PortRange.any(),
    protocol: ProtoMatch = .any,
};

/// Packet direction.
pub const Direction = enum {
    inbound,
    outbound,
    both,
};

/// Packet metadata for matching.
pub const PacketInfo = struct {
    src_addr: [4]u8,
    dst_addr: [4]u8,
    src_port: u16,
    dst_port: u16,
    protocol: ProtoMatch,
    direction: Direction,
};

/// Packet filter engine.
pub const PacketFilter = struct {
    rules: [max_rules]Rule = [_]Rule{.{}} ** max_rules,
    rule_count: usize = 0,
    /// Default action when no rule matches.
    default_action: Action = .allow,

    pub fn init() PacketFilter {
        return .{};
    }

    /// Add a rule. Returns true on success, false if table is full.
    pub fn addRule(self: *PacketFilter, rule: Rule) bool {
        if (self.rule_count >= max_rules) return false;
        var i: usize = 0;
        while (i < max_rules) : (i += 1) {
            if (!self.rules[i].active) {
                self.rules[i] = rule;
                self.rules[i].active = true;
                self.rule_count += 1;
                return true;
            }
        }
        return false;
    }

    /// Remove all rules.
    pub fn clearRules(self: *PacketFilter) void {
        for (&self.rules) |*r| r.active = false;
        self.rule_count = 0;
    }

    /// Evaluate a packet against the rule table. Returns allow/deny.
    pub fn evaluate(self: *const PacketFilter, pkt: PacketInfo) Action {
        for (&self.rules) |*rule| {
            if (!rule.active) continue;
            if (self.ruleMatches(rule, pkt)) return rule.action;
        }
        return self.default_action;
    }

    fn ruleMatches(_: *const PacketFilter, rule: *const Rule, pkt: PacketInfo) bool {
        // Direction
        if (rule.direction != .both and rule.direction != pkt.direction) return false;

        // Protocol
        if (rule.protocol != .any and rule.protocol != pkt.protocol) return false;

        // Source prefix
        if (rule.src_prefix) |prefix| {
            if (!prefix.containsIpv4(pkt.src_addr)) return false;
        }

        // Destination prefix
        if (rule.dst_prefix) |prefix| {
            if (!prefix.containsIpv4(pkt.dst_addr)) return false;
        }

        // Ports
        if (!rule.src_port.matches(pkt.src_port)) return false;
        if (!rule.dst_port.matches(pkt.dst_port)) return false;

        return true;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "PacketFilter: default allow" {
    const pf = PacketFilter.init();
    const action = pf.evaluate(.{
        .src_addr = .{ 10, 0, 0, 1 },
        .dst_addr = .{ 10, 0, 0, 2 },
        .src_port = 5000,
        .dst_port = 80,
        .protocol = .tcp,
        .direction = .inbound,
    });
    try testing.expectEqual(Action.allow, action);
}

test "PacketFilter: deny rule blocks traffic" {
    var pf = PacketFilter.init();
    try testing.expect(pf.addRule(.{
        .action = .deny,
        .direction = .inbound,
        .dst_port = PortRange.exact(22),
        .protocol = .tcp,
    }));

    // SSH traffic denied
    const a1 = pf.evaluate(.{
        .src_addr = .{ 10, 0, 0, 1 },
        .dst_addr = .{ 10, 0, 0, 2 },
        .src_port = 5000,
        .dst_port = 22,
        .protocol = .tcp,
        .direction = .inbound,
    });
    try testing.expectEqual(Action.deny, a1);

    // HTTP traffic allowed (no matching rule)
    const a2 = pf.evaluate(.{
        .src_addr = .{ 10, 0, 0, 1 },
        .dst_addr = .{ 10, 0, 0, 2 },
        .src_port = 5000,
        .dst_port = 80,
        .protocol = .tcp,
        .direction = .inbound,
    });
    try testing.expectEqual(Action.allow, a2);
}

test "PacketFilter: prefix matching" {
    var pf = PacketFilter.init();
    pf.default_action = .deny;

    // Allow from 10.0.0.0/8
    try testing.expect(pf.addRule(.{
        .action = .allow,
        .direction = .inbound,
        .src_prefix = route_mod.Prefix.fromIpv4(.{ 10, 0, 0, 0 }, 8),
    }));

    const a1 = pf.evaluate(.{
        .src_addr = .{ 10, 1, 2, 3 },
        .dst_addr = .{ 192, 168, 1, 1 },
        .src_port = 0,
        .dst_port = 0,
        .protocol = .any,
        .direction = .inbound,
    });
    try testing.expectEqual(Action.allow, a1);

    const a2 = pf.evaluate(.{
        .src_addr = .{ 192, 168, 1, 100 },
        .dst_addr = .{ 192, 168, 1, 1 },
        .src_port = 0,
        .dst_port = 0,
        .protocol = .any,
        .direction = .inbound,
    });
    try testing.expectEqual(Action.deny, a2);
}

test "PacketFilter: first match wins" {
    var pf = PacketFilter.init();

    // Rule 1: allow port 443
    try testing.expect(pf.addRule(.{
        .action = .allow,
        .direction = .inbound,
        .dst_port = PortRange.exact(443),
        .protocol = .tcp,
    }));
    // Rule 2: deny all TCP
    try testing.expect(pf.addRule(.{
        .action = .deny,
        .direction = .inbound,
        .protocol = .tcp,
    }));

    // Port 443 should match rule 1 first → allow
    const a1 = pf.evaluate(.{
        .src_addr = .{ 1, 2, 3, 4 },
        .dst_addr = .{ 5, 6, 7, 8 },
        .src_port = 5000,
        .dst_port = 443,
        .protocol = .tcp,
        .direction = .inbound,
    });
    try testing.expectEqual(Action.allow, a1);

    // Port 80 should match rule 2 → deny
    const a2 = pf.evaluate(.{
        .src_addr = .{ 1, 2, 3, 4 },
        .dst_addr = .{ 5, 6, 7, 8 },
        .src_port = 5000,
        .dst_port = 80,
        .protocol = .tcp,
        .direction = .inbound,
    });
    try testing.expectEqual(Action.deny, a2);
}

test "PacketFilter: port range" {
    var pf = PacketFilter.init();
    pf.default_action = .deny;

    // Allow high ports (1024-65535)
    try testing.expect(pf.addRule(.{
        .action = .allow,
        .direction = .outbound,
        .dst_port = .{ .min = 1024, .max = 65535 },
    }));

    const a1 = pf.evaluate(.{
        .src_addr = .{ 10, 0, 0, 1 },
        .dst_addr = .{ 10, 0, 0, 2 },
        .src_port = 5000,
        .dst_port = 8080,
        .protocol = .any,
        .direction = .outbound,
    });
    try testing.expectEqual(Action.allow, a1);

    const a2 = pf.evaluate(.{
        .src_addr = .{ 10, 0, 0, 1 },
        .dst_addr = .{ 10, 0, 0, 2 },
        .src_port = 5000,
        .dst_port = 22,
        .protocol = .any,
        .direction = .outbound,
    });
    try testing.expectEqual(Action.deny, a2);
}
