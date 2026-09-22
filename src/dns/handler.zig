// DNS handler: query/response parsing, split DNS, caching, response mapping.
//
// Sans-IO: parses and transforms DNS wire-format data, no network I/O.
// Fixed-size structures for zero-allocation hot path.

const std = @import("std");

// DNS wire format constants
pub const HEADER_LEN = 12;
pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

pub const SERVICE_IP_V4 = [4]u8{ 100, 200, 100, 200 };

/// DNS header (12 bytes).
pub const Header = struct {
    id: u16 = 0,
    flags: u16 = 0,
    qd_count: u16 = 0,
    an_count: u16 = 0,
    ns_count: u16 = 0,
    ar_count: u16 = 0,

    pub fn parse(data: []const u8) ?Header {
        if (data.len < HEADER_LEN) return null;
        return Header{
            .id = readU16(data, 0),
            .flags = readU16(data, 2),
            .qd_count = readU16(data, 4),
            .an_count = readU16(data, 6),
            .ns_count = readU16(data, 8),
            .ar_count = readU16(data, 10),
        };
    }

    pub fn isQuery(self: Header) bool {
        return (self.flags & 0x8000) == 0;
    }

    pub fn isResponse(self: Header) bool {
        return (self.flags & 0x8000) != 0;
    }
};

/// Parsed DNS question.
pub const Question = struct {
    name: [256]u8 = [_]u8{0} ** 256,
    name_len: u8 = 0,
    qtype: u16 = 0,
    qclass: u16 = 0,
    /// Offset in the packet where the question ends.
    end_offset: usize = 0,

    pub fn nameSlice(self: *const Question) []const u8 {
        return self.name[0..self.name_len];
    }
};

/// Parsed DNS answer (A or AAAA).
pub const Answer = struct {
    name: [256]u8 = [_]u8{0} ** 256,
    name_len: u8 = 0,
    atype: u16 = 0,
    aclass: u16 = 0,
    ttl: u32 = 0,
    rdlength: u16 = 0,
    /// Offset where rdata starts in the packet.
    rdata_offset: usize = 0,
    /// For A records
    ipv4: [4]u8 = [_]u8{0} ** 4,
    /// For AAAA records
    ipv6: [16]u8 = [_]u8{0} ** 16,
};

/// The longest name the wire format allows in the dotted form this builds:
/// RFC 1035 4.2 caps the encoded name at 255 bytes, which is a length byte
/// per label plus the root's zero, so the dots-instead-of-lengths form of
/// the longest encodable name is two bytes shorter.
const max_name_len = 253;

/// The most compression pointers one name may follow. Real names use one or
/// two — Go's dnsmessage stops at ten — and the count is what bounds the
/// work per name, both against the cycles described below and against a
/// message full of names that each walk a long chain.
const max_pointer_jumps = 16;

/// Parse a DNS name from wire format. Returns decoded name and bytes
/// consumed, or null for a name that is not one.
///
/// A compression pointer must point backwards, which is what RFC 1035 4.1.4
/// means by naming a prior occurrence, and a name may follow only so many of
/// them. Both are needed. The backward rule alone does not terminate: a
/// label moves the position forward again, so
///
///     [111] = pointer to 100, [100] = pointer to 50, [50] = a 60-byte label
///
/// walks 111 → 100 → 50 → 111 with every jump pointing backwards. What stops
/// it is running out of jumps, or out of name — and without either, two
/// bytes anyone can send (a pointer to its own offset) is parsed until the
/// machine is switched off.
pub fn parseName(data: []const u8, offset: usize, out: []u8) ?struct { len: u8, consumed: usize } {
    var pos = offset;
    var out_pos: usize = 0;
    var consumed: usize = 0;
    var jumped = false;
    var terminated = false;
    var jumps: usize = 0;

    while (pos < data.len) {
        const label_len = data[pos];

        if (label_len == 0) {
            if (!jumped) consumed = pos + 1 - offset;
            terminated = true;
            break;
        }

        // Pointer (compression)
        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= data.len) return null;
            const ptr_offset = (@as(usize, label_len & 0x3F) << 8) | @as(usize, data[pos + 1]);
            if (ptr_offset >= pos) return null;
            jumps += 1;
            if (jumps > max_pointer_jumps) return null;
            if (!jumped) consumed = pos + 2 - offset;
            jumped = true;
            pos = ptr_offset;
            continue;
        }

        // The two other label types are reserved and have never been
        // assigned, so a byte carrying one is not a name either.
        if ((label_len & 0xC0) != 0) return null;

        // Regular label
        pos += 1;
        if (pos + label_len > data.len) return null;
        if (out_pos + label_len + 1 > out.len) return null;
        if (out_pos + label_len + 1 > max_name_len) return null;

        if (out_pos > 0) {
            out[out_pos] = '.';
            out_pos += 1;
        }
        @memcpy(out[out_pos .. out_pos + label_len], data[pos .. pos + label_len]);
        out_pos += label_len;
        pos += label_len;
    }

    // A name that runs off the end of the packet is a truncated name, not a
    // short one: reporting it as parsed hands the caller a length that
    // reaches past the data it came from.
    if (!terminated) return null;

    return .{ .len = @intCast(out_pos), .consumed = consumed };
}

/// Parse the first question from a DNS packet.
pub fn parseQuestion(data: []const u8) ?Question {
    const hdr = Header.parse(data) orelse return null;
    if (hdr.qd_count == 0) return null;

    var q = Question{};
    const name_result = parseName(data, HEADER_LEN, &q.name) orelse return null;
    q.name_len = name_result.len;

    const qtype_offset = HEADER_LEN + name_result.consumed;
    if (qtype_offset + 4 > data.len) return null;
    q.qtype = readU16(data, qtype_offset);
    q.qclass = readU16(data, qtype_offset + 2);
    q.end_offset = qtype_offset + 4;
    return q;
}

/// Parse answers from a DNS response packet.
pub fn parseAnswers(data: []const u8, out: []Answer) usize {
    const hdr = Header.parse(data) orelse return 0;
    if (hdr.an_count == 0) return 0;

    // Skip question section
    const q = parseQuestion(data) orelse return 0;
    var pos = q.end_offset;
    var count: usize = 0;

    var i: u16 = 0;
    while (i < hdr.an_count and count < out.len) : (i += 1) {
        if (pos >= data.len) break;

        var ans = Answer{};
        const name_result = parseName(data, pos, &ans.name) orelse break;
        ans.name_len = name_result.len;
        pos += name_result.consumed;

        if (pos + 10 > data.len) break;
        ans.atype = readU16(data, pos);
        ans.aclass = readU16(data, pos + 2);
        ans.ttl = readU32(data, pos + 4);
        ans.rdlength = readU16(data, pos + 8);
        pos += 10;

        ans.rdata_offset = pos;
        if (pos + ans.rdlength > data.len) break;

        if (ans.atype == TYPE_A and ans.rdlength == 4) {
            @memcpy(&ans.ipv4, data[pos .. pos + 4]);
        } else if (ans.atype == TYPE_AAAA and ans.rdlength == 16) {
            @memcpy(&ans.ipv6, data[pos .. pos + 16]);
        }

        pos += ans.rdlength;
        out[count] = ans;
        count += 1;
    }
    return count;
}

/// DNS resolver address.
pub const Resolver = struct {
    addr: [4]u8 = .{ 8, 8, 8, 8 },
    port: u16 = 53,
};

/// Split DNS route entry.
pub const DnsRoute = struct {
    suffix: [128]u8 = [_]u8{0} ** 128,
    suffix_len: u8 = 0,
    resolver: Resolver = .{},
    active: bool = false,

    pub fn suffixSlice(self: *const DnsRoute) []const u8 {
        return self.suffix[0..self.suffix_len];
    }
};

/// DNS cache entry.
pub const CacheEntry = struct {
    name: [256]u8 = [_]u8{0} ** 256,
    name_len: u8 = 0,
    qtype: u16 = 0,
    /// Cached response data
    response: [512]u8 = undefined,
    response_len: u16 = 0,
    /// Absolute expiry time (ms)
    expiry_ms: u64 = 0,
    active: bool = false,
    last_used_ms: u64 = 0,
};

/// DNS configuration.
pub const DnsConfig = struct {
    default_resolvers: [4]Resolver = [_]Resolver{.{}} ** 4,
    default_resolver_count: u8 = 1,
    routes: [32]DnsRoute = [_]DnsRoute{.{}} ** 32,
    route_count: u8 = 0,
    search_domains: [8][64]u8 = [_][64]u8{[_]u8{0} ** 64} ** 8,
    search_domain_lens: [8]u8 = [_]u8{0} ** 8,
    search_domain_count: u8 = 0,
    hosts: [32]HostEntry = [_]HostEntry{.{}} ** 32,
    host_count: u8 = 0,

    pub const HostEntry = struct {
        name: [128]u8 = [_]u8{0} ** 128,
        name_len: u8 = 0,
        addr: [4]u8 = .{ 0, 0, 0, 0 },
        active: bool = false,
    };

    pub fn addRoute(self: *DnsConfig, suffix: []const u8, resolver: Resolver) bool {
        if (self.route_count >= 32) return false;
        var route = &self.routes[self.route_count];
        const len = @min(suffix.len, 128);
        @memcpy(route.suffix[0..len], suffix[0..len]);
        route.suffix_len = @intCast(len);
        route.resolver = resolver;
        route.active = true;
        self.route_count += 1;
        return true;
    }

    pub fn addHost(self: *DnsConfig, name: []const u8, addr: [4]u8) bool {
        if (self.host_count >= 32) return false;
        var h = &self.hosts[self.host_count];
        const len = @min(name.len, 128);
        @memcpy(h.name[0..len], name[0..len]);
        h.name_len = @intCast(len);
        h.addr = addr;
        h.active = true;
        self.host_count += 1;
        return true;
    }

    /// Find the resolver for a domain using longest suffix match.
    pub fn resolverForDomain(self: *const DnsConfig, domain: []const u8) Resolver {
        var best_len: u8 = 0;
        var best_resolver: ?Resolver = null;

        for (self.routes[0..self.route_count]) |*route| {
            if (!route.active) continue;
            const suffix = route.suffixSlice();
            if (suffix.len > domain.len) continue;
            if (std.mem.endsWith(u8, domain, suffix) and route.suffix_len > best_len) {
                best_len = route.suffix_len;
                best_resolver = route.resolver;
            }
        }
        if (best_resolver) |r| return r;
        if (self.default_resolver_count > 0) return self.default_resolvers[0];
        return .{};
    }

    /// Look up a static host entry.
    pub fn lookupHost(self: *const DnsConfig, name: []const u8) ?[4]u8 {
        for (self.hosts[0..self.host_count]) |*h| {
            if (!h.active) continue;
            if (std.mem.eql(u8, h.name[0..h.name_len], name)) return h.addr;
        }
        return null;
    }
};

/// DNS Cache (fixed LRU).
pub fn DnsCache(comptime capacity: usize) type {
    return struct {
        const Self = @This();

        entries: [capacity]CacheEntry = [_]CacheEntry{.{}} ** capacity,
        count: usize = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn lookup(self: *Self, name: []const u8, qtype: u16, now_ms: u64) ?[]const u8 {
            for (&self.entries) |*entry| {
                if (!entry.active) continue;
                if (entry.qtype != qtype) continue;
                if (!std.mem.eql(u8, entry.name[0..entry.name_len], name)) continue;

                if (now_ms >= entry.expiry_ms) {
                    entry.active = false;
                    self.count -= 1;
                    return null;
                }
                entry.last_used_ms = now_ms;
                return entry.response[0..entry.response_len];
            }
            return null;
        }

        pub fn insert(self: *Self, name: []const u8, qtype: u16, response: []const u8, ttl_ms: u64, now_ms: u64) void {
            const idx = self.findSlot(now_ms);
            var entry = &self.entries[idx];
            if (!entry.active) self.count += 1;

            entry.active = true;
            entry.qtype = qtype;
            const name_len = @min(name.len, 256);
            @memcpy(entry.name[0..name_len], name[0..name_len]);
            entry.name_len = @intCast(name_len);
            const resp_len = @min(response.len, 512);
            @memcpy(entry.response[0..resp_len], response[0..resp_len]);
            entry.response_len = @intCast(resp_len);
            entry.expiry_ms = now_ms + ttl_ms;
            entry.last_used_ms = now_ms;
        }

        fn findSlot(self: *Self, now_ms: u64) usize {
            // First: find inactive slot
            for (&self.entries, 0..) |*entry, i| {
                if (!entry.active) return i;
            }
            // Second: find expired
            for (&self.entries, 0..) |*entry, i| {
                if (now_ms >= entry.expiry_ms) return i;
            }
            // Third: evict LRU
            var lru_idx: usize = 0;
            var lru_time: u64 = std.math.maxInt(u64);
            for (&self.entries, 0..) |*entry, i| {
                if (entry.last_used_ms < lru_time) {
                    lru_time = entry.last_used_ms;
                    lru_idx = i;
                }
            }
            return lru_idx;
        }
    };
}

/// Resolve result from the handler.
pub const ResolveResult = union(enum) {
    /// Static host match — respond directly with A record.
    static_host: [4]u8,
    /// Forward to this resolver.
    forward: Resolver,
    /// Cached response available.
    cached: []const u8,
};

/// DNS Handler.
pub const DnsHandler = struct {
    config: DnsConfig = .{},
    cache: DnsCache(256) = DnsCache(256).init(),
    response_mapper: ?*const fn (question_name: []const u8, response: []u8, response_len: usize) usize = null,

    pub fn init(config: DnsConfig) DnsHandler {
        return .{ .config = config };
    }

    /// Process a DNS query. Returns what action to take.
    pub fn handleQuery(self: *DnsHandler, query_data: []const u8, now_ms: u64) ?ResolveResult {
        const question = parseQuestion(query_data) orelse return null;
        const name = question.nameSlice();

        // Static host?
        if (question.qtype == TYPE_A) {
            if (self.config.lookupHost(name)) |addr| {
                return .{ .static_host = addr };
            }
        }

        // Cached?
        if (self.cache.lookup(name, question.qtype, now_ms)) |cached| {
            return .{ .cached = cached };
        }

        // Determine resolver
        const resolver = self.config.resolverForDomain(name);
        return .{ .forward = resolver };
    }

    /// After receiving a response from upstream, apply response mapper and cache.
    pub fn processResponse(self: *DnsHandler, query_data: []const u8, response: []u8, response_len: usize, now_ms: u64) usize {
        var final_len = response_len;

        // Apply response mapper (App Linker DNS rewrite)
        if (self.response_mapper) |mapper| {
            const question = parseQuestion(query_data) orelse return final_len;
            final_len = mapper(question.nameSlice(), response, response_len);
        }

        // Cache the response
        if (parseQuestion(query_data)) |question| {
            const name = question.nameSlice();
            // Default 60s TTL for caching
            self.cache.insert(name, question.qtype, response[0..final_len], 60_000, now_ms);
        }

        return final_len;
    }
};

// Helpers
fn readU16(data: []const u8, offset: usize) u16 {
    return (@as(u16, data[offset]) << 8) | @as(u16, data[offset + 1]);
}

fn readU32(data: []const u8, offset: usize) u32 {
    return (@as(u32, data[offset]) << 24) | (@as(u32, data[offset + 1]) << 16) |
        (@as(u32, data[offset + 2]) << 8) | @as(u32, data[offset + 3]);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

// Helper: build a minimal DNS query packet for "example.com" A
fn buildTestQuery() [29]u8 {
    var pkt: [29]u8 = undefined;
    // Header: ID=0x1234, flags=0x0100 (standard query), QDCOUNT=1
    pkt[0] = 0x12;
    pkt[1] = 0x34;
    pkt[2] = 0x01;
    pkt[3] = 0x00;
    pkt[4] = 0x00;
    pkt[5] = 0x01; // QDCOUNT
    pkt[6] = 0x00;
    pkt[7] = 0x00; // ANCOUNT
    pkt[8] = 0x00;
    pkt[9] = 0x00;
    pkt[10] = 0x00;
    pkt[11] = 0x00;
    // Question: 7example3com0
    pkt[12] = 7;
    @memcpy(pkt[13..20], "example");
    pkt[20] = 3;
    @memcpy(pkt[21..24], "com");
    pkt[24] = 0; // end
    // QTYPE=A(1), QCLASS=IN(1)
    pkt[25] = 0x00;
    pkt[26] = 0x01;
    pkt[27] = 0x00;
    pkt[28] = 0x01;
    return pkt;
}

test "DNS: parse question" {
    const pkt = buildTestQuery();
    const q = parseQuestion(&pkt).?;
    try testing.expectEqualSlices(u8, "example.com", q.nameSlice());
    try testing.expectEqual(TYPE_A, q.qtype);
    try testing.expectEqual(CLASS_IN, q.qclass);
}

test "DNS: parse name with pointer" {
    // Simulate a name with compression pointer
    var data: [32]u8 = undefined;
    // At offset 0: label "foo" (4 bytes: len=3 + "foo")
    data[0] = 3;
    @memcpy(data[1..4], "foo");
    data[4] = 0; // end

    // At offset 5: pointer to offset 0
    data[5] = 0xC0;
    data[6] = 0x00;

    var out: [256]u8 = undefined;
    const result = parseName(&data, 5, &out).?;
    try testing.expectEqualSlices(u8, "foo", out[0..result.len]);
    try testing.expectEqual(@as(usize, 2), result.consumed);
}

test "DNS: parse A answer" {
    // Build response: header + question + 1 A answer
    var pkt: [45]u8 = undefined;
    // Header
    pkt[0] = 0x12;
    pkt[1] = 0x34;
    pkt[2] = 0x81;
    pkt[3] = 0x80; // response
    pkt[4] = 0x00;
    pkt[5] = 0x01; // QDCOUNT=1
    pkt[6] = 0x00;
    pkt[7] = 0x01; // ANCOUNT=1
    pkt[8] = 0x00;
    pkt[9] = 0x00;
    pkt[10] = 0x00;
    pkt[11] = 0x00;
    // Question: 3foo0
    pkt[12] = 3;
    @memcpy(pkt[13..16], "foo");
    pkt[16] = 0;
    pkt[17] = 0x00;
    pkt[18] = 0x01; // A
    pkt[19] = 0x00;
    pkt[20] = 0x01; // IN
    // Answer: pointer to question name
    pkt[21] = 0xC0;
    pkt[22] = 12;
    // TYPE=A
    pkt[23] = 0x00;
    pkt[24] = 0x01;
    // CLASS=IN
    pkt[25] = 0x00;
    pkt[26] = 0x01;
    // TTL=300
    pkt[27] = 0x00;
    pkt[28] = 0x00;
    pkt[29] = 0x01;
    pkt[30] = 0x2C;
    // RDLENGTH=4
    pkt[31] = 0x00;
    pkt[32] = 0x04;
    // RDATA: 1.2.3.4
    pkt[33] = 1;
    pkt[34] = 2;
    pkt[35] = 3;
    pkt[36] = 4;
    // Pad
    @memset(pkt[37..45], 0);

    var answers: [4]Answer = undefined;
    const count = parseAnswers(pkt[0..37], &answers);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqual(TYPE_A, answers[0].atype);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, &answers[0].ipv4);
    try testing.expectEqual(@as(u32, 300), answers[0].ttl);
}

test "DNS: config resolver selection" {
    var config = DnsConfig{};
    config.default_resolvers[0] = .{ .addr = .{ 8, 8, 8, 8 } };
    config.default_resolver_count = 1;

    _ = config.addRoute(".corp.example.com", .{ .addr = .{ 10, 0, 0, 53 } });
    _ = config.addRoute(".example.com", .{ .addr = .{ 10, 0, 1, 53 } });

    // Exact suffix match: longest wins
    const r1 = config.resolverForDomain("api.corp.example.com");
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 53 }, &r1.addr);

    // Shorter suffix match
    const r2 = config.resolverForDomain("www.example.com");
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 1, 53 }, &r2.addr);

    // No match → default
    const r3 = config.resolverForDomain("google.com");
    try testing.expectEqualSlices(u8, &[_]u8{ 8, 8, 8, 8 }, &r3.addr);
}

test "DNS: cache insert and lookup" {
    var cache = DnsCache(4).init();
    cache.insert("example.com", TYPE_A, "response1", 10_000, 1000);

    // Hit
    const hit = cache.lookup("example.com", TYPE_A, 5000);
    try testing.expect(hit != null);
    try testing.expectEqualSlices(u8, "response1", hit.?);

    // Miss: wrong type
    try testing.expect(cache.lookup("example.com", TYPE_AAAA, 5000) == null);

    // Miss: expired
    try testing.expect(cache.lookup("example.com", TYPE_A, 12000) == null);
}

test "DNS: cache LRU eviction" {
    var cache = DnsCache(2).init();
    cache.insert("a.com", TYPE_A, "resp_a", 60_000, 0);
    cache.insert("b.com", TYPE_A, "resp_b", 60_000, 100);

    // Touch a.com
    _ = cache.lookup("a.com", TYPE_A, 200);

    // Insert c.com → should evict b.com (least recently used)
    cache.insert("c.com", TYPE_A, "resp_c", 60_000, 300);

    try testing.expect(cache.lookup("a.com", TYPE_A, 400) != null);
    try testing.expect(cache.lookup("b.com", TYPE_A, 400) == null);
    try testing.expect(cache.lookup("c.com", TYPE_A, 400) != null);
}

test "DNS: handler static host" {
    var config = DnsConfig{};
    _ = config.addHost("myhost.local", .{ 10, 0, 0, 99 });

    var handler = DnsHandler.init(config);

    // Build query for "myhost.local" A
    var pkt: [30]u8 = undefined;
    pkt[0] = 0x00;
    pkt[1] = 0x01;
    pkt[2] = 0x01;
    pkt[3] = 0x00;
    pkt[4] = 0x00;
    pkt[5] = 0x01;
    @memset(pkt[6..12], 0);
    pkt[12] = 6;
    @memcpy(pkt[13..19], "myhost");
    pkt[19] = 5;
    @memcpy(pkt[20..25], "local");
    pkt[25] = 0;
    pkt[26] = 0x00;
    pkt[27] = 0x01;
    pkt[28] = 0x00;
    pkt[29] = 0x01;

    const result = handler.handleQuery(&pkt, 0).?;
    switch (result) {
        .static_host => |addr| try testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 99 }, &addr),
        else => return error.TestUnexpectedResult,
    }
}

test "dns: a name that points at itself is not a name" {
    // Two bytes: a compression pointer to its own offset. Following it was
    // once an endless walk, which is a whole daemon stopped by a packet.
    var pkt: [32]u8 = [_]u8{0} ** 32;
    pkt[HEADER_LEN] = 0xC0;
    pkt[HEADER_LEN + 1] = HEADER_LEN;
    var out: [256]u8 = undefined;
    try std.testing.expect(parseName(&pkt, HEADER_LEN, &out) == null);

    // A pointer that names something later in the packet goes the same way.
    pkt[12] = 0xC0;
    pkt[13] = 20;
    pkt[20] = 0;
    try std.testing.expect(parseName(&pkt, 12, &out) == null);

    // And a cycle that never points forward: a label between the pointers
    // moves the position back to where it started. Every jump here names a
    // prior offset, so the backward rule alone does not stop this one.
    var cycle: [128]u8 = [_]u8{0} ** 128;
    cycle[111] = 0xC0;
    cycle[112] = 100;
    cycle[100] = 0xC0;
    cycle[101] = 50;
    cycle[50] = 60;
    @memset(cycle[51..111], 'x');
    try std.testing.expect(parseName(&cycle, 111, &out) == null);
}

test "dns: a name may follow a chain of pointers, but not an endless one" {
    // "a" at 20, then names that each point at the one before: the chain is
    // followed to the end and the labels come out in order.
    var pkt: [64]u8 = [_]u8{0} ** 64;
    pkt[20] = 1;
    pkt[21] = 'a';
    pkt[22] = 0;
    var pos: usize = 24;
    var target: u8 = 20;
    var letter: u8 = 'b';
    while (pos + 4 <= 48) : (pos += 4) {
        pkt[pos] = 1;
        pkt[pos + 1] = letter;
        pkt[pos + 2] = 0xC0;
        pkt[pos + 3] = target;
        target = @intCast(pos);
        letter += 1;
    }
    var out: [256]u8 = undefined;
    const last = parseName(&pkt, pos - 4, &out).?;
    try std.testing.expectEqualStrings("g.f.e.d.c.b.a", out[0..last.len]);

    // Seventeen pointers in a row is past what one name may follow, even
    // with a label of its own on the end of each.
    var deep: [512]u8 = [_]u8{0} ** 512;
    deep[0] = 1;
    deep[1] = 'z';
    deep[2] = 0;
    var dpos: usize = 4;
    var dtarget: u8 = 0;
    while (dpos + 4 <= 4 + 17 * 4) : (dpos += 4) {
        deep[dpos] = 1;
        deep[dpos + 1] = 'y';
        deep[dpos + 2] = 0xC0;
        deep[dpos + 3] = dtarget;
        dtarget = @intCast(dpos);
    }
    try std.testing.expect(parseName(&deep, dpos - 4, &out) == null);
}

test "dns: a compressed name is read through its pointer" {
    // "a.example" at offset 4, then "b" + a pointer to the "example" label.
    var pkt: [64]u8 = [_]u8{0} ** 64;
    pkt[4] = 1;
    pkt[5] = 'a';
    pkt[6] = 7;
    @memcpy(pkt[7..14], "example");
    pkt[14] = 0;
    pkt[20] = 1;
    pkt[21] = 'b';
    pkt[22] = 0xC0;
    pkt[23] = 6; // the "example" label

    var out: [256]u8 = undefined;
    const full = parseName(&pkt, 4, &out).?;
    try std.testing.expectEqualStrings("a.example", out[0..full.len]);
    try std.testing.expectEqual(@as(usize, 11), full.consumed);

    const compressed = parseName(&pkt, 20, &out).?;
    try std.testing.expectEqualStrings("b.example", out[0..compressed.len]);
    // Two labels' worth of bytes plus the pointer, and nothing beyond it.
    try std.testing.expectEqual(@as(usize, 4), compressed.consumed);
}

test "dns: a name is refused when it is too long, reserved or truncated" {
    var out: [256]u8 = undefined;

    // Four 63-byte labels encode to 257 bytes, two past what the format
    // allows, even though the dotted form is 255 and would fit a buffer.
    var long: [400]u8 = [_]u8{0} ** 400;
    var pos: usize = 0;
    for (0..4) |_| {
        long[pos] = 63;
        @memset(long[pos + 1 .. pos + 64], 'x');
        pos += 64;
    }
    long[pos] = 0;
    try std.testing.expect(parseName(&long, 0, &out) == null);
    // Including for a caller whose buffer would have held it: the limit is
    // the format's, not the buffer's.
    var big: [512]u8 = undefined;
    try std.testing.expect(parseName(&long, 0, &big) == null);

    // The longest name that does encode: 63 + 63 + 63 + 61 and the dots
    // between them is 253, which is 255 once the length bytes and the root
    // are back.
    var longest: [260]u8 = [_]u8{0} ** 260;
    pos = 0;
    for ([_]u8{ 63, 63, 63, 61 }) |label| {
        longest[pos] = label;
        @memset(longest[pos + 1 .. pos + 1 + label], 'x');
        pos += 1 + label;
    }
    longest[pos] = 0;
    const ok = parseName(&longest, 0, &big).?;
    try std.testing.expectEqual(@as(u8, 253), ok.len);

    // A reserved label type (0x40 and 0x80 are neither a label nor a
    // pointer).
    var reserved: [8]u8 = [_]u8{0} ** 8;
    reserved[0] = 0x40;
    try std.testing.expect(parseName(&reserved, 0, &out) == null);
    reserved[0] = 0x80;
    try std.testing.expect(parseName(&reserved, 0, &out) == null);

    // A name whose last label runs to the end of the packet with no root
    // label after it.
    var truncated: [4]u8 = .{ 3, 'a', 'b', 'c' };
    try std.testing.expect(parseName(&truncated, 0, &out) == null);
}
