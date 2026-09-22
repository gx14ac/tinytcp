// DNS handler: query/response parsing, split DNS, caching, response mapping.
//
// Sans-IO: parses and transforms DNS wire-format data, no network I/O.
// Fixed-size structures for zero-allocation hot path.

const std = @import("std");

// DNS wire format constants
pub const HEADER_LEN = 12;
pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
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
            // Backwards, and no further back than the header: the twelve
            // bytes in front of the first question are counts and flags, not
            // labels.
            if (ptr_offset >= pos or ptr_offset < HEADER_LEN) return null;
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

/// The name inside a record whose rdata is one: CNAME, PTR and NS. The
/// message is needed as well as the record, because the name in there may
/// point back into it. Returns its length in `out`, or null for a record
/// that holds something else or a name that is not one.
pub fn rdataName(ans: *const Answer, data: []const u8, out: []u8) ?u8 {
    switch (ans.atype) {
        TYPE_CNAME, TYPE_PTR, TYPE_NS => {},
        else => return null,
    }
    if (!rdataFits(ans, data)) return null;
    const r = parseName(data, ans.rdata_offset, out) orelse return null;
    // parseName stops at the end of the message; the record says where its
    // own data stops, and a name may not run past that into the next one.
    if (r.consumed > ans.rdlength) return null;
    return r.len;
}

/// Whether the record's data is inside the message it came in.
fn rdataFits(ans: *const Answer, data: []const u8) bool {
    return ans.rdata_offset + ans.rdlength <= data.len;
}

/// What an SRV record says about where a service is, its target name aside
/// (that one comes out of `srvTarget`).
pub const Srv = struct {
    priority: u16,
    weight: u16,
    port: u16,
};

pub fn srvFields(ans: *const Answer, data: []const u8) ?Srv {
    if (ans.atype != TYPE_SRV) return null;
    if (ans.rdlength < 6) return null;
    if (!rdataFits(ans, data)) return null;
    return .{
        .priority = readU16(data, ans.rdata_offset),
        .weight = readU16(data, ans.rdata_offset + 2),
        .port = readU16(data, ans.rdata_offset + 4),
    };
}

/// The target of an SRV record, which follows its three numbers.
pub fn srvTarget(ans: *const Answer, data: []const u8, out: []u8) ?u8 {
    if (ans.atype != TYPE_SRV) return null;
    if (ans.rdlength < 7) return null;
    if (!rdataFits(ans, data)) return null;
    const r = parseName(data, ans.rdata_offset + 6, out) orelse return null;
    if (r.consumed > ans.rdlength - 6) return null;
    return r.len;
}

/// The strings of a TXT record, which is a sequence of length-prefixed ones
/// rather than a single string. Call next() until it returns null.
pub const TxtStrings = struct {
    data: []const u8,
    pos: usize,
    end: usize,

    pub fn next(self: *TxtStrings) ?[]const u8 {
        if (self.pos >= self.end) return null;
        const len = self.data[self.pos];
        const start = self.pos + 1;
        if (start + len > self.end) {
            self.pos = self.end;
            return null;
        }
        self.pos = start + len;
        return self.data[start .. start + len];
    }
};

pub fn txtStrings(ans: *const Answer, data: []const u8) ?TxtStrings {
    if (ans.atype != TYPE_TXT) return null;
    if (!rdataFits(ans, data)) return null;
    return .{ .data = data, .pos = ans.rdata_offset, .end = ans.rdata_offset + ans.rdlength };
}

/// Write a name in wire format: each label with its length in front, and a
/// zero at the end. Returns the bytes written, or null when the name does
/// not fit or is not one.
pub fn encodeName(out: []u8, name: []const u8) ?usize {
    var written: usize = 0;
    // The root is a name with no labels, written as "." as often as it is
    // written as nothing at all.
    var rest = if (name.len == 1 and name[0] == '.') name[1..] else name;
    while (rest.len > 0) {
        const dot = std.mem.indexOfScalar(u8, rest, '.') orelse rest.len;
        if (dot == 0 or dot > 63) return null;
        if (written + 1 + dot + 1 > out.len) return null;
        out[written] = @intCast(dot);
        @memcpy(out[written + 1 ..][0..dot], rest[0..dot]);
        written += 1 + dot;
        rest = if (dot == rest.len) rest[dot..] else rest[dot + 1 ..];
    }
    if (written + 1 > out.len) return null;
    if (written + 1 > 255) return null;
    out[written] = 0;
    return written + 1;
}

/// Builds a response to a query in the caller's buffer.
///
/// The query's header and question come back as the wire format requires,
/// and each answer names the question with a pointer to it rather than
/// spelling the name out again — which is what a resolver's answers look
/// like, and keeps a response to a long name inside a datagram.
pub const ResponseBuilder = struct {
    const Self = @This();
    /// The question's name always starts right after the header, so this is
    /// the pointer every answer uses to name it.
    const name_pointer = [2]u8{ 0xC0, HEADER_LEN };

    buf: []u8,
    len: usize,
    an_count: u16 = 0,

    /// Copy the header and question of `query`, with the response bit set.
    /// Null for a query this cannot answer: one without a question, or a
    /// buffer too small for the question it asks.
    pub fn init(buf: []u8, query: []const u8) ?Self {
        const q = parseQuestion(query) orelse return null;
        if (q.end_offset > query.len) return null;
        if (buf.len < q.end_offset) return null;
        @memcpy(buf[0..q.end_offset], query[0..q.end_offset]);
        // QR and AA set, RA and the rcode clear, and the query's RD kept:
        // this answers from what it knows rather than from a recursion it
        // did.
        const flags = (readU16(query, 2) & 0x0100) | 0x8400;
        writeU16(buf, 2, flags);
        writeU16(buf, 4, 1); // one question, whatever the query claimed
        writeU16(buf, 6, 0);
        writeU16(buf, 8, 0);
        writeU16(buf, 10, 0);
        return .{ .buf = buf, .len = q.end_offset };
    }

    /// Truncated: an answer did not fit, so the client is told to ask again
    /// over TCP rather than being handed what did fit as the whole story.
    const flag_tc: u16 = 0x0200;

    pub fn addA(self: *Self, ttl: u32, addr: [4]u8) bool {
        return self.addRecord(TYPE_A, ttl, &addr);
    }

    pub fn addAAAA(self: *Self, ttl: u32, addr: [16]u8) bool {
        return self.addRecord(TYPE_AAAA, ttl, &addr);
    }

    /// A PTR record, whose rdata is the name it points at.
    pub fn addPtr(self: *Self, ttl: u32, name: []const u8) bool {
        var encoded: [256]u8 = undefined;
        const n = encodeName(&encoded, name) orelse return false;
        return self.addRecord(TYPE_PTR, ttl, encoded[0..n]);
    }

    /// Say there is no such name, which comes with no answers: any that
    /// were added go, rather than being sent alongside a code that says
    /// there is nothing to send.
    pub fn setNameError(self: *Self) void {
        writeU16(self.buf, 2, (readU16(self.buf, 2) & 0xFFF0) | 3);
        self.len = questionEnd(self.buf);
        self.an_count = 0;
    }

    /// Where the question this was built from ends, which is where answers
    /// start and where dropping them puts the length back.
    fn questionEnd(buf: []const u8) usize {
        const q = parseQuestion(buf) orelse return HEADER_LEN;
        return q.end_offset;
    }

    /// The response, with its answer count filled in.
    pub fn finish(self: *Self) []const u8 {
        writeU16(self.buf, 6, self.an_count);
        return self.buf[0..self.len];
    }

    fn addRecord(self: *Self, rtype: u16, ttl: u32, rdata: []const u8) bool {
        const need = name_pointer.len + 2 + 2 + 4 + 2 + rdata.len;
        if (self.len + need > self.buf.len or self.an_count == std.math.maxInt(u16)) {
            writeU16(self.buf, 2, readU16(self.buf, 2) | flag_tc);
            return false;
        }
        var at = self.len;
        @memcpy(self.buf[at..][0..name_pointer.len], &name_pointer);
        at += name_pointer.len;
        writeU16(self.buf, at, rtype);
        writeU16(self.buf, at + 2, CLASS_IN);
        writeU32(self.buf, at + 4, ttl);
        writeU16(self.buf, at + 8, @intCast(rdata.len));
        at += 10;
        @memcpy(self.buf[at..][0..rdata.len], rdata);
        self.len = at + rdata.len;
        self.an_count += 1;
        return true;
    }
};

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

fn writeU16(data: []u8, offset: usize, value: u16) void {
    std.mem.writeInt(u16, data[offset..][0..2], value, .big);
}

fn writeU32(data: []u8, offset: usize, value: u32) void {
    std.mem.writeInt(u32, data[offset..][0..4], value, .big);
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
    // Simulate a name with compression pointer. The offsets are where they
    // would be in a message, since a pointer names one: the first question
    // starts after the twelve-byte header.
    var data: [48]u8 = undefined;
    // At offset 12: label "foo" (4 bytes: len=3 + "foo")
    data[12] = 3;
    @memcpy(data[13..16], "foo");
    data[16] = 0; // end

    // At offset 17: pointer to offset 12
    data[17] = 0xC0;
    data[18] = 12;

    var out: [256]u8 = undefined;
    const result = parseName(&data, 17, &out).?;
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

    // So does one that names the header, where there are no labels.
    pkt[12] = 0xC0;
    pkt[13] = 4; // QDCOUNT
    try std.testing.expect(parseName(&pkt, 12, &out) == null);

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
    deep[12] = 1;
    deep[13] = 'z';
    deep[14] = 0;
    var dpos: usize = 16;
    var dtarget: u8 = 12;
    while (dpos + 4 <= 16 + 17 * 4) : (dpos += 4) {
        deep[dpos] = 1;
        deep[dpos + 1] = 'y';
        deep[dpos + 2] = 0xC0;
        deep[dpos + 3] = dtarget;
        dtarget = @intCast(dpos);
    }
    try std.testing.expect(parseName(&deep, dpos - 4, &out) == null);
}

test "dns: a compressed name is read through its pointer" {
    // "a.example" where the first question goes, then "b" + a pointer to
    // the "example" label inside it.
    var pkt: [64]u8 = [_]u8{0} ** 64;
    pkt[12] = 1;
    pkt[13] = 'a';
    pkt[14] = 7;
    @memcpy(pkt[15..22], "example");
    pkt[22] = 0;
    pkt[30] = 1;
    pkt[31] = 'b';
    pkt[32] = 0xC0;
    pkt[33] = 14; // the "example" label

    var out: [256]u8 = undefined;
    const full = parseName(&pkt, 12, &out).?;
    try std.testing.expectEqualStrings("a.example", out[0..full.len]);
    try std.testing.expectEqual(@as(usize, 11), full.consumed);

    const compressed = parseName(&pkt, 30, &out).?;
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

test "dns: a response is built and reads back as one" {
    const query = buildTestQuery();
    var buf: [512]u8 = undefined;

    var b = ResponseBuilder.init(&buf, &query).?;
    try testing.expect(b.addA(60, .{ 100, 64, 0, 7 }));
    try testing.expect(b.addAAAA(60, [_]u8{ 0xfd, 0x7a } ++ [_]u8{0} ** 13 ++ [_]u8{7}));
    const response = b.finish();

    // The query's id comes back, the response bit is set, and the question
    // is the one that was asked.
    const hdr = Header.parse(response).?;
    try testing.expectEqual(@as(u16, 0x1234), hdr.id);
    try testing.expect(hdr.isResponse());
    try testing.expectEqual(@as(u16, 1), hdr.qd_count);
    try testing.expectEqual(@as(u16, 2), hdr.an_count);

    const q = parseQuestion(response).?;
    try testing.expectEqualStrings("example.com", q.nameSlice());
    try testing.expectEqual(TYPE_A, q.qtype);

    // And the answers name that question through their pointer to it.
    var answers: [4]Answer = undefined;
    try testing.expectEqual(@as(usize, 2), parseAnswers(response, &answers));
    try testing.expectEqualStrings("example.com", answers[0].name[0..answers[0].name_len]);
    try testing.expectEqual(TYPE_A, answers[0].atype);
    try testing.expectEqual(@as(u32, 60), answers[0].ttl);
    try testing.expectEqualSlices(u8, &.{ 100, 64, 0, 7 }, &answers[0].ipv4);
    try testing.expectEqual(TYPE_AAAA, answers[1].atype);
    try testing.expectEqual(@as(u8, 0xfd), answers[1].ipv6[0]);
    try testing.expectEqual(@as(u8, 7), answers[1].ipv6[15]);
}

test "dns: a PTR answer carries a name, and a name error carries none" {
    const query = buildTestQuery();
    var buf: [512]u8 = undefined;

    var b = ResponseBuilder.init(&buf, &query).?;
    try testing.expect(b.addPtr(120, "host.mesh.example"));
    const response = b.finish();

    var answers: [2]Answer = undefined;
    try testing.expectEqual(@as(usize, 1), parseAnswers(response, &answers));
    try testing.expectEqual(TYPE_PTR, answers[0].atype);
    var name: [256]u8 = undefined;
    const len = rdataName(&answers[0], response, &name).?;
    try testing.expectEqualStrings("host.mesh.example", name[0..len]);
    // The other record types do not hold a name.
    answers[0].atype = TYPE_A;
    try testing.expect(rdataName(&answers[0], response, &name) == null);

    // A name error comes with no answers, including ones already added.
    var nx = ResponseBuilder.init(&buf, &query).?;
    try testing.expect(nx.addA(60, .{ 1, 2, 3, 4 }));
    nx.setNameError();
    const refused = nx.finish();
    try testing.expectEqual(@as(u16, 0), Header.parse(refused).?.an_count);
    try testing.expectEqual(@as(u16, 3), Header.parse(refused).?.flags & 0x000F);
    try testing.expectEqual(parseQuestion(refused).?.end_offset, refused.len);
}

test "dns: a response stops when the buffer is full" {
    const query = buildTestQuery();
    // Room for the question and one A record, and not two.
    var buf: [29 + 16]u8 = undefined;
    var b = ResponseBuilder.init(&buf, &query).?;
    try testing.expect(b.addA(60, .{ 1, 2, 3, 4 }));
    try testing.expect(!b.addA(60, .{ 5, 6, 7, 8 }));
    const partial = b.finish();
    try testing.expectEqual(@as(u16, 1), Header.parse(partial).?.an_count);
    // And it says so: the answer that did not fit is what the truncation
    // bit is for, so the client asks again over TCP instead of taking this
    // for the whole answer.
    try testing.expect(Header.parse(partial).?.flags & 0x0200 != 0);

    // And a buffer that cannot even hold the question is refused outright.
    var tiny: [20]u8 = undefined;
    try testing.expect(ResponseBuilder.init(&tiny, &query) == null);
}

test "dns: names go to the wire and come back" {
    var wire: [64]u8 = undefined;
    const n = encodeName(&wire, "a.example").?;
    try testing.expectEqual(@as(usize, 11), n);
    try testing.expectEqualSlices(u8, &.{ 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0 }, wire[0..n]);

    var back: [256]u8 = undefined;
    const r = parseName(wire[0..n], 0, &back).?;
    try testing.expectEqualStrings("a.example", back[0..r.len]);

    // A label of its own is a name, and so is the root — written either as
    // nothing or as a lone dot.
    try testing.expectEqual(@as(usize, 3), encodeName(&wire, "a").?);
    try testing.expectEqual(@as(usize, 1), encodeName(&wire, "").?);
    try testing.expectEqual(@as(usize, 1), encodeName(&wire, ".").?);
    try testing.expectEqual(@as(u8, 0), wire[0]);

    // An empty label, a label past 63 bytes, and a name past the buffer are
    // not names.
    try testing.expect(encodeName(&wire, "a..b") == null);
    var long: [80]u8 = [_]u8{'x'} ** 80;
    try testing.expect(encodeName(&wire, &long) == null);
    var small: [4]u8 = undefined;
    try testing.expect(encodeName(&small, "example") == null);
}

test "dns: an SRV record's numbers and target, and a TXT record's strings" {
    // Build a response by hand: SRV and TXT are what a resolver reads rather
    // than what this builds, so the wire bytes come first.
    var pkt: [128]u8 = [_]u8{0} ** 128;
    const query = buildTestQuery();
    @memcpy(pkt[0..query.len], &query);
    writeU16(&pkt, 2, 0x8400);
    writeU16(&pkt, 6, 2); // two answers

    var at: usize = query.len;
    // SRV: priority 10, weight 20, port 8080, target "svc.example"
    pkt[at] = 0xC0;
    pkt[at + 1] = HEADER_LEN;
    writeU16(&pkt, at + 2, TYPE_SRV);
    writeU16(&pkt, at + 4, CLASS_IN);
    writeU32(&pkt, at + 6, 30);
    var target: [32]u8 = undefined;
    const tlen = encodeName(&target, "svc.example").?;
    writeU16(&pkt, at + 10, @intCast(6 + tlen));
    writeU16(&pkt, at + 12, 10);
    writeU16(&pkt, at + 14, 20);
    writeU16(&pkt, at + 16, 8080);
    @memcpy(pkt[at + 18 ..][0..tlen], target[0..tlen]);
    at += 18 + tlen;

    // TXT: two strings in one record.
    pkt[at] = 0xC0;
    pkt[at + 1] = HEADER_LEN;
    writeU16(&pkt, at + 2, TYPE_TXT);
    writeU16(&pkt, at + 4, CLASS_IN);
    writeU32(&pkt, at + 6, 30);
    writeU16(&pkt, at + 10, 4 + 4);
    pkt[at + 12] = 3;
    @memcpy(pkt[at + 13 ..][0..3], "one");
    pkt[at + 16] = 3;
    @memcpy(pkt[at + 17 ..][0..3], "two");
    at += 20;

    var answers: [4]Answer = undefined;
    try testing.expectEqual(@as(usize, 2), parseAnswers(pkt[0..at], &answers));

    const srv = srvFields(&answers[0], pkt[0..at]).?;
    try testing.expectEqual(@as(u16, 10), srv.priority);
    try testing.expectEqual(@as(u16, 20), srv.weight);
    try testing.expectEqual(@as(u16, 8080), srv.port);
    var name: [256]u8 = undefined;
    const len = srvTarget(&answers[0], pkt[0..at], &name).?;
    try testing.expectEqualStrings("svc.example", name[0..len]);

    var strings = txtStrings(&answers[1], pkt[0..at]).?;
    try testing.expectEqualStrings("one", strings.next().?);
    try testing.expectEqualStrings("two", strings.next().?);
    try testing.expect(strings.next() == null);

    // Asking the wrong record for either of them says no.
    try testing.expect(srvFields(&answers[1], pkt[0..at]) == null);
    try testing.expect(txtStrings(&answers[0], pkt[0..at]) == null);
}

test "dns: a record's data cannot reach past the length it declares" {
    const query = buildTestQuery();
    var pkt: [128]u8 = [_]u8{0} ** 128;
    @memcpy(pkt[0..query.len], &query);
    writeU16(&pkt, 2, 0x8400);
    writeU16(&pkt, 6, 1);

    // A PTR record whose rdlength says four bytes, with a name behind it
    // that runs on for more: the name is inside the message, so only the
    // record's own length says where it stops.
    const at: usize = query.len;
    pkt[at] = 0xC0;
    pkt[at + 1] = HEADER_LEN;
    writeU16(&pkt, at + 2, TYPE_PTR);
    writeU16(&pkt, at + 4, CLASS_IN);
    writeU32(&pkt, at + 6, 30);
    writeU16(&pkt, at + 10, 4);
    var name_wire: [32]u8 = undefined;
    const n = encodeName(&name_wire, "long.example").?;
    @memcpy(pkt[at + 12 ..][0..n], name_wire[0..n]);
    const end = at + 12 + n;

    var answers: [2]Answer = undefined;
    try testing.expectEqual(@as(usize, 1), parseAnswers(pkt[0..end], &answers));
    var out: [256]u8 = undefined;
    try testing.expect(rdataName(&answers[0], pkt[0..end], &out) == null);

    // With the length it actually needs, the same bytes read fine.
    writeU16(&pkt, at + 10, @intCast(n));
    _ = parseAnswers(pkt[0..end], &answers);
    const len = rdataName(&answers[0], pkt[0..end], &out).?;
    try testing.expectEqualStrings("long.example", out[0..len]);

    // A record that claims more data than the message holds is not read at
    // all, whatever its type.
    answers[0].rdlength = 200;
    try testing.expect(rdataName(&answers[0], pkt[0..end], &out) == null);
    answers[0].atype = TYPE_SRV;
    try testing.expect(srvFields(&answers[0], pkt[0..end]) == null);
    try testing.expect(srvTarget(&answers[0], pkt[0..end], &out) == null);
    answers[0].atype = TYPE_TXT;
    try testing.expect(txtStrings(&answers[0], pkt[0..end]) == null);
}
