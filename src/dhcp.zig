// DHCP Client (RFC 2131).
//
// Implements the DHCP state machine for automatic IPv4 address configuration:
// - DISCOVER → OFFER → REQUEST → ACK (DORA)
// - Lease management with T1 (renewal) and T2 (rebind) timers
// - DHCP Decline on address conflict
//
// Sans-IO: produces DHCP packets; caller sends as UDP broadcast on port 67/68.

const std = @import("std");

/// DHCP message types.
pub const MsgType = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
    _,
};

/// DHCP client state.
pub const State = enum {
    init,
    selecting,
    requesting,
    bound,
    renewing,
    rebinding,
};

/// DHCP option codes.
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_T1: u8 = 58;
const OPT_T2: u8 = 59;
const OPT_END: u8 = 255;

/// DHCP magic cookie.
const MAGIC_COOKIE = [4]u8{ 99, 130, 83, 99 };

/// DHCP lease information.
pub const Lease = struct {
    ip: [4]u8 = .{0} ** 4,
    subnet_mask: [4]u8 = .{ 255, 255, 255, 0 },
    gateway: [4]u8 = .{0} ** 4,
    dns: [4]u8 = .{0} ** 4,
    server_id: [4]u8 = .{0} ** 4,
    lease_time_s: u32 = 0,
    t1_s: u32 = 0,
    t2_s: u32 = 0,
};

/// DHCP client output action.
pub const DhcpAction = union(enum) {
    none,
    /// Send this DHCP packet (as UDP to 255.255.255.255:67).
    send: SendBuf,
    /// Lease acquired — configure the interface.
    configured: Lease,
    /// Lease lost — deconfigure.
    deconfigured,
};

/// Buffer for an outbound DHCP packet (UDP payload).
pub const SendBuf = struct {
    data: [576]u8 = undefined,
    len: usize = 0,
};

/// DHCP Client state machine.
pub const Client = struct {
    state: State = .init,
    mac: [6]u8 = .{0} ** 6,
    xid: u32 = 0x12345678,
    lease: Lease = .{},
    lease_start_ms: u64 = 0,
    last_send_ms: u64 = 0,
    retransmit_count: u8 = 0,

    pub fn init(mac: [6]u8, xid: u32) Client {
        return .{ .mac = mac, .xid = xid };
    }

    /// Start DHCP discovery. Returns a DISCOVER packet to send.
    pub fn start(self: *Client, now_ms: u64) DhcpAction {
        self.state = .selecting;
        self.last_send_ms = now_ms;
        self.retransmit_count = 0;
        return self.buildDiscover();
    }

    /// Process an incoming DHCP message (UDP payload from port 67).
    pub fn onMessage(self: *Client, now_ms: u64, data: []const u8) DhcpAction {
        const msg = parseDhcpMessage(data) orelse return .none;

        // Verify xid matches
        if (msg.xid != self.xid) return .none;

        // Extract message type from options
        const msg_type = msg.msgType() orelse return .none;

        switch (self.state) {
            .selecting => {
                if (msg_type == .offer) {
                    // Accept first offer
                    self.lease.ip = msg.yiaddr;
                    self.extractOptions(&msg);
                    self.state = .requesting;
                    self.last_send_ms = now_ms;
                    self.retransmit_count = 0;
                    return self.buildRequest(false);
                }
            },
            .requesting => {
                if (msg_type == .ack) {
                    self.lease.ip = msg.yiaddr;
                    self.extractOptions(&msg);
                    self.state = .bound;
                    self.lease_start_ms = now_ms;
                    return .{ .configured = self.lease };
                }
                if (msg_type == .nak) {
                    self.state = .init;
                    return .deconfigured;
                }
            },
            .renewing, .rebinding => {
                if (msg_type == .ack) {
                    self.extractOptions(&msg);
                    self.state = .bound;
                    self.lease_start_ms = now_ms;
                    return .{ .configured = self.lease };
                }
                if (msg_type == .nak) {
                    self.state = .init;
                    return .deconfigured;
                }
            },
            else => {},
        }
        return .none;
    }

    /// Tick the DHCP state machine — handles retransmission and lease timers.
    pub fn tick(self: *Client, now_ms: u64) DhcpAction {
        switch (self.state) {
            .selecting => {
                // Retransmit DISCOVER after timeout (exponential backoff, max 64s)
                const timeout = retransmitTimeout(self.retransmit_count);
                if (now_ms >= self.last_send_ms + timeout) {
                    self.retransmit_count +|= 1;
                    self.last_send_ms = now_ms;
                    return self.buildDiscover();
                }
            },
            .requesting => {
                const timeout = retransmitTimeout(self.retransmit_count);
                if (now_ms >= self.last_send_ms + timeout) {
                    if (self.retransmit_count >= 4) {
                        // Give up, restart
                        self.state = .init;
                        return .deconfigured;
                    }
                    self.retransmit_count +|= 1;
                    self.last_send_ms = now_ms;
                    return self.buildRequest(false);
                }
            },
            .bound => {
                const elapsed_s = (now_ms - self.lease_start_ms) / 1000;
                const t1 = if (self.lease.t1_s > 0) self.lease.t1_s else self.lease.lease_time_s / 2;
                const t2 = if (self.lease.t2_s > 0) self.lease.t2_s else self.lease.lease_time_s * 7 / 8;

                if (elapsed_s >= t2) {
                    self.state = .rebinding;
                    self.last_send_ms = now_ms;
                    self.retransmit_count = 0;
                    return self.buildRequest(true);
                } else if (elapsed_s >= t1) {
                    self.state = .renewing;
                    self.last_send_ms = now_ms;
                    self.retransmit_count = 0;
                    return self.buildRequest(true);
                }
            },
            .renewing => {
                const elapsed_s = (now_ms - self.lease_start_ms) / 1000;
                const t2 = if (self.lease.t2_s > 0) self.lease.t2_s else self.lease.lease_time_s * 7 / 8;
                if (elapsed_s >= t2) {
                    self.state = .rebinding;
                    self.last_send_ms = now_ms;
                    self.retransmit_count = 0;
                    return self.buildRequest(true);
                }
                const timeout = retransmitTimeout(self.retransmit_count);
                if (now_ms >= self.last_send_ms + timeout) {
                    self.retransmit_count +|= 1;
                    self.last_send_ms = now_ms;
                    return self.buildRequest(true);
                }
            },
            .rebinding => {
                const elapsed_s = (now_ms - self.lease_start_ms) / 1000;
                if (elapsed_s >= self.lease.lease_time_s) {
                    self.state = .init;
                    return .deconfigured;
                }
                const timeout = retransmitTimeout(self.retransmit_count);
                if (now_ms >= self.last_send_ms + timeout) {
                    self.retransmit_count +|= 1;
                    self.last_send_ms = now_ms;
                    return self.buildRequest(true);
                }
            },
            .init => {},
        }
        return .none;
    }

    /// Send a DHCP Decline (address conflict detected).
    pub fn decline(self: *Client, now_ms: u64) DhcpAction {
        _ = now_ms;
        const pkt = self.buildDecline();
        self.state = .init;
        return pkt;
    }

    /// Send a DHCP Release.
    pub fn release(self: *Client) DhcpAction {
        const pkt = self.buildRelease();
        self.state = .init;
        return pkt;
    }

    // -- Internal builders --

    fn buildDiscover(self: *const Client) DhcpAction {
        var buf: SendBuf = .{};
        var offset: usize = 0;

        offset = self.writeHeader(&buf.data, offset, 1, .{0} ** 4); // ciaddr = 0
        offset = writeOption(&buf.data, offset, OPT_MSG_TYPE, &[_]u8{@intFromEnum(MsgType.discover)});
        buf.data[offset] = OPT_END;
        offset += 1;

        buf.len = @max(offset, 300); // Minimum DHCP packet size
        return .{ .send = buf };
    }

    fn buildRequest(self: *const Client, renew: bool) DhcpAction {
        var buf: SendBuf = .{};
        var offset: usize = 0;

        const ciaddr = if (renew) self.lease.ip else [4]u8{ 0, 0, 0, 0 };
        offset = self.writeHeader(&buf.data, offset, 1, ciaddr);
        offset = writeOption(&buf.data, offset, OPT_MSG_TYPE, &[_]u8{@intFromEnum(MsgType.request)});
        if (!renew) {
            offset = writeOption(&buf.data, offset, OPT_REQUESTED_IP, &self.lease.ip);
            offset = writeOption(&buf.data, offset, OPT_SERVER_ID, &self.lease.server_id);
        }
        buf.data[offset] = OPT_END;
        offset += 1;

        buf.len = @max(offset, 300);
        return .{ .send = buf };
    }

    fn buildDecline(self: *const Client) DhcpAction {
        var buf: SendBuf = .{};
        var offset: usize = 0;

        offset = self.writeHeader(&buf.data, offset, 1, .{0} ** 4);
        offset = writeOption(&buf.data, offset, OPT_MSG_TYPE, &[_]u8{@intFromEnum(MsgType.decline)});
        offset = writeOption(&buf.data, offset, OPT_REQUESTED_IP, &self.lease.ip);
        offset = writeOption(&buf.data, offset, OPT_SERVER_ID, &self.lease.server_id);
        buf.data[offset] = OPT_END;
        offset += 1;

        buf.len = @max(offset, 300);
        return .{ .send = buf };
    }

    fn buildRelease(self: *const Client) DhcpAction {
        var buf: SendBuf = .{};
        var offset: usize = 0;

        offset = self.writeHeader(&buf.data, offset, 1, self.lease.ip);
        offset = writeOption(&buf.data, offset, OPT_MSG_TYPE, &[_]u8{@intFromEnum(MsgType.release)});
        offset = writeOption(&buf.data, offset, OPT_SERVER_ID, &self.lease.server_id);
        buf.data[offset] = OPT_END;
        offset += 1;

        buf.len = @max(offset, 300);
        return .{ .send = buf };
    }

    fn writeHeader(self: *const Client, buf: []u8, offset: usize, op: u8, ciaddr: [4]u8) usize {
        var off = offset;
        buf[off] = op; // op: 1=request
        off += 1;
        buf[off] = 1; // htype: Ethernet
        off += 1;
        buf[off] = 6; // hlen
        off += 1;
        buf[off] = 0; // hops
        off += 1;
        std.mem.writeInt(u32, buf[off..][0..4], self.xid, .big);
        off += 4;
        @memset(buf[off .. off + 4], 0); // secs + flags
        off += 4;
        @memcpy(buf[off .. off + 4], &ciaddr); // ciaddr
        off += 4;
        @memset(buf[off .. off + 12], 0); // yiaddr + siaddr + giaddr
        off += 12;
        @memcpy(buf[off .. off + 6], &self.mac); // chaddr (first 6)
        off += 6;
        @memset(buf[off .. off + 10], 0); // chaddr padding
        off += 10;
        @memset(buf[off .. off + 192], 0); // sname + file
        off += 192;
        @memcpy(buf[off .. off + 4], &MAGIC_COOKIE);
        off += 4;
        return off;
    }

    fn extractOptions(self: *Client, msg: *const DhcpMessage) void {
        var off: usize = 0;
        while (off < msg.options.len) {
            const code = msg.options[off];
            if (code == OPT_END) break;
            if (code == 0) {
                off += 1;
                continue;
            }
            if (off + 1 >= msg.options.len) break;
            const len = msg.options[off + 1];
            off += 2;
            if (off + len > msg.options.len) break;

            const data = msg.options[off .. off + len];
            switch (code) {
                OPT_SUBNET_MASK => if (len == 4) {
                    self.lease.subnet_mask = data[0..4].*;
                },
                OPT_ROUTER => if (len >= 4) {
                    self.lease.gateway = data[0..4].*;
                },
                OPT_DNS => if (len >= 4) {
                    self.lease.dns = data[0..4].*;
                },
                OPT_LEASE_TIME => if (len == 4) {
                    self.lease.lease_time_s = std.mem.readInt(u32, data[0..4], .big);
                },
                OPT_SERVER_ID => if (len == 4) {
                    self.lease.server_id = data[0..4].*;
                },
                OPT_T1 => if (len == 4) {
                    self.lease.t1_s = std.mem.readInt(u32, data[0..4], .big);
                },
                OPT_T2 => if (len == 4) {
                    self.lease.t2_s = std.mem.readInt(u32, data[0..4], .big);
                },
                else => {},
            }
            off += len;
        }
    }
};

/// Parsed DHCP message fields.
const DhcpMessage = struct {
    op: u8,
    xid: u32,
    yiaddr: [4]u8,
    siaddr: [4]u8,
    chaddr: [6]u8,
    options: []const u8,

    fn msgType(self: *const DhcpMessage) ?MsgType {
        var off: usize = 0;
        while (off < self.options.len) {
            const code = self.options[off];
            if (code == OPT_END) break;
            if (code == 0) {
                off += 1;
                continue;
            }
            if (off + 1 >= self.options.len) break;
            const len = self.options[off + 1];
            off += 2;
            if (off + len > self.options.len) break;
            if (code == OPT_MSG_TYPE and len == 1) {
                return @enumFromInt(self.options[off]);
            }
            off += len;
        }
        return null;
    }
};

fn parseDhcpMessage(data: []const u8) ?DhcpMessage {
    // Minimum: header(236) + magic(4) + 1 option byte
    if (data.len < 241) return null;

    // Verify magic cookie at offset 236
    if (!std.mem.eql(u8, data[236..240], &MAGIC_COOKIE)) return null;

    return DhcpMessage{
        .op = data[0],
        .xid = std.mem.readInt(u32, data[4..8], .big),
        .yiaddr = data[16..20].*,
        .siaddr = data[20..24].*,
        .chaddr = data[28..34].*,
        .options = data[240..],
    };
}

fn writeOption(buf: []u8, offset: usize, code: u8, value: []const u8) usize {
    var off = offset;
    buf[off] = code;
    off += 1;
    buf[off] = @intCast(value.len);
    off += 1;
    @memcpy(buf[off .. off + value.len], value);
    off += value.len;
    return off;
}

fn retransmitTimeout(count: u8) u64 {
    // Exponential backoff: 4s, 8s, 16s, 32s, 64s
    const base: u64 = 4000;
    const shift: u6 = @intCast(@min(count, 4));
    return base << shift;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "DHCP: discover → offer → request → ack" {
    var client = Client.init(.{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 }, 0xAABBCCDD);

    // Start → sends DISCOVER
    const discover = client.start(0);
    switch (discover) {
        .send => |buf| {
            try testing.expect(buf.len >= 300);
            try testing.expectEqual(@as(u8, 1), buf.data[0]); // op=BOOTREQUEST
            // Verify magic cookie at offset 236
            try testing.expectEqualSlices(u8, &MAGIC_COOKIE, buf.data[236..240]);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(State.selecting, client.state);

    // Simulate OFFER response
    var offer_pkt: [300]u8 = .{0} ** 300;
    offer_pkt[0] = 2; // op=BOOTREPLY
    std.mem.writeInt(u32, offer_pkt[4..8], 0xAABBCCDD, .big); // xid
    offer_pkt[16] = 192;
    offer_pkt[17] = 168;
    offer_pkt[18] = 1;
    offer_pkt[19] = 100; // yiaddr
    @memcpy(offer_pkt[236..240], &MAGIC_COOKIE);
    // Message type option
    offer_pkt[240] = OPT_MSG_TYPE;
    offer_pkt[241] = 1;
    offer_pkt[242] = @intFromEnum(MsgType.offer);
    // Server ID
    offer_pkt[243] = OPT_SERVER_ID;
    offer_pkt[244] = 4;
    offer_pkt[245] = 192;
    offer_pkt[246] = 168;
    offer_pkt[247] = 1;
    offer_pkt[248] = 1;
    // Lease time
    offer_pkt[249] = OPT_LEASE_TIME;
    offer_pkt[250] = 4;
    std.mem.writeInt(u32, offer_pkt[251..255], 3600, .big);
    offer_pkt[255] = OPT_END;

    const req_action = client.onMessage(1000, &offer_pkt);
    switch (req_action) {
        .send => {}, // REQUEST sent
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(State.requesting, client.state);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 100 }, &client.lease.ip);

    // Simulate ACK
    var ack_pkt: [300]u8 = .{0} ** 300;
    ack_pkt[0] = 2;
    std.mem.writeInt(u32, ack_pkt[4..8], 0xAABBCCDD, .big);
    ack_pkt[16] = 192;
    ack_pkt[17] = 168;
    ack_pkt[18] = 1;
    ack_pkt[19] = 100;
    @memcpy(ack_pkt[236..240], &MAGIC_COOKIE);
    ack_pkt[240] = OPT_MSG_TYPE;
    ack_pkt[241] = 1;
    ack_pkt[242] = @intFromEnum(MsgType.ack);
    ack_pkt[243] = OPT_SUBNET_MASK;
    ack_pkt[244] = 4;
    ack_pkt[245] = 255;
    ack_pkt[246] = 255;
    ack_pkt[247] = 255;
    ack_pkt[248] = 0;
    ack_pkt[249] = OPT_ROUTER;
    ack_pkt[250] = 4;
    ack_pkt[251] = 192;
    ack_pkt[252] = 168;
    ack_pkt[253] = 1;
    ack_pkt[254] = 1;
    ack_pkt[255] = OPT_LEASE_TIME;
    ack_pkt[256] = 4;
    std.mem.writeInt(u32, ack_pkt[257..261], 3600, .big);
    ack_pkt[261] = OPT_END;

    const configured = client.onMessage(2000, &ack_pkt);
    switch (configured) {
        .configured => |lease| {
            try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 100 }, &lease.ip);
            try testing.expectEqualSlices(u8, &[_]u8{ 255, 255, 255, 0 }, &lease.subnet_mask);
            try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 1 }, &lease.gateway);
            try testing.expectEqual(@as(u32, 3600), lease.lease_time_s);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(State.bound, client.state);
}

test "DHCP: retransmit timeout" {
    var client = Client.init(.{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 }, 0x11223344);
    _ = client.start(0);

    // Before timeout: no action
    const a1 = client.tick(3999);
    switch (a1) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }

    // After 4s: retransmit
    const a2 = client.tick(4001);
    switch (a2) {
        .send => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(u8, 1), client.retransmit_count);
}

test "DHCP: renewal at T1" {
    var client = Client.init(.{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 }, 0x55667788);
    client.state = .bound;
    client.lease = .{
        .ip = .{ 10, 0, 0, 50 },
        .server_id = .{ 10, 0, 0, 1 },
        .lease_time_s = 3600,
        .t1_s = 1800,
        .t2_s = 3150,
    };
    client.lease_start_ms = 0;

    // Before T1: no action
    const a1 = client.tick(1799_000);
    switch (a1) {
        .none => {},
        else => return error.TestUnexpectedResult,
    }

    // At T1: transitions to renewing
    const a2 = client.tick(1800_001);
    switch (a2) {
        .send => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(State.renewing, client.state);
}

test "DHCP: lease expiry" {
    var client = Client.init(.{ 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 }, 0x99AABBCC);
    client.state = .rebinding;
    client.lease = .{
        .ip = .{ 10, 0, 0, 50 },
        .lease_time_s = 100,
    };
    client.lease_start_ms = 0;
    client.last_send_ms = 0;

    // Past lease time: deconfigured
    const a = client.tick(100_001);
    switch (a) {
        .deconfigured => {},
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(State.init, client.state);
}
