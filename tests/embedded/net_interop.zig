// QEMU + TAP network interop test for tinytcp.
//
// Runs tinytcp as a bare-metal TCP echo server on QEMU mps2-an385 with
// LAN9118 NIC connected to a host TAP device. The test validates:
//   - ARP: responds to who-has requests (host can resolve our MAC)
//   - ICMP: responds to echo requests (host can ping us)
//   - TCP: echo server on port 7777 (host can connect and exchange data)
//
// Network config:
//   Host TAP: 10.0.0.1/24
//   QEMU NIC: 10.0.0.2/24, MAC 02:00:00:00:00:01

const std = @import("std");
const tinytcp = @import("tinytcp");
const lan9118 = @import("lan9118.zig");

const StackT = tinytcp.full_stack.FullStackFull(4, tinytcp.config.Config.embedded_minimal, SmallEndpoint);
const SmallEndpoint = tinytcp.link.ChannelEndpointWith(8, 1600);
const Event = tinytcp.full_stack.Event;

const OUR_IP = [4]u8{ 10, 0, 0, 2 };
const OUR_MAC = lan9118.mac_addr;
const BROADCAST_MAC = [6]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;

// --- SysTick (Cortex-M3 0xE000E010) ---

const SYST_CSR: *volatile u32 = @ptrFromInt(0xE000E010);
const SYST_RVR: *volatile u32 = @ptrFromInt(0xE000E014);
const SYST_CVR: *volatile u32 = @ptrFromInt(0xE000E018);

const SYSTICK_RELOAD: u32 = 25_000_000 / 1000 - 1; // 25MHz → 1ms

var systick_ms: u64 = 0;

fn initSysTick() void {
    SYST_RVR.* = SYSTICK_RELOAD;
    SYST_CVR.* = 0;
    SYST_CSR.* = 0x5; // ENABLE | CLKSOURCE(processor), no interrupt
}

fn getTick() u64 {
    if (SYST_CSR.* & (1 << 16) != 0) {
        systick_ms += 1;
    }
    return systick_ms;
}

// --- Semihosting ---

const semihosting = struct {
    fn call(reason: u32, arg: u32) u32 {
        return asm volatile ("bkpt 0xab"
            : [ret] "={r0}" (-> u32),
            : [r0] "{r0}" (reason),
              [r1] "{r1}" (arg),
        );
    }

    fn puts(msg: [*:0]const u8) void {
        _ = call(0x04, @intFromPtr(msg));
    }

    fn exit() noreturn {
        _ = call(0x18, 0x20023);
        unreachable;
    }
};

// --- Ethernet helpers ---

fn readU16Big(data: []const u8, off: usize) u16 {
    return (@as(u16, data[off]) << 8) | @as(u16, data[off + 1]);
}

fn writeU16Big(data: []u8, off: usize, val: u16) void {
    data[off] = @truncate(val >> 8);
    data[off + 1] = @truncate(val);
}

fn buildEthHdr(out: []u8, dst: [6]u8, src: [6]u8, etype: u16) void {
    @memcpy(out[0..6], &dst);
    @memcpy(out[6..12], &src);
    writeU16Big(out, 12, etype);
}


// --- ARP handler ---

fn handleArp(frame: []const u8, tx_buf: []u8) ?usize {
    if (frame.len < 42) return null;
    const arp = frame[14..];

    if (readU16Big(arp, 0) != 1) return null; // htype = Ethernet
    if (readU16Big(arp, 2) != 0x0800) return null; // ptype = IPv4
    if (arp[4] != 6 or arp[5] != 4) return null;
    if (readU16Big(arp, 6) != 1) return null; // oper = REQUEST

    const target_ip = arp[24..28];
    if (!std.mem.eql(u8, target_ip, &OUR_IP)) return null;

    buildEthHdr(tx_buf, frame[6..12].*, OUR_MAC, ETHERTYPE_ARP);

    var reply = tx_buf[14..];
    writeU16Big(reply, 0, 1);
    writeU16Big(reply, 2, 0x0800);
    reply[4] = 6;
    reply[5] = 4;
    writeU16Big(reply, 6, 2); // REPLY
    @memcpy(reply[8..14], &OUR_MAC);
    @memcpy(reply[14..18], &OUR_IP);
    @memcpy(reply[18..24], frame[6..12]);
    @memcpy(reply[24..28], arp[14..18]);

    return 42;
}

// --- IPv4 handler ---

fn handleIpv4(frame: []const u8, s: *StackT, ep: *SmallEndpoint, tx_buf: []u8) void {
    if (frame.len < 34) return;

    const pkt = frame[14..];
    const event = s.injectPacket(getTick(), pkt);
    processEvent(s, event);
    drainOutbound(ep, frame[6..12], tx_buf);
}

fn processEvent(s: *StackT, event: Event) void {
    switch (event) {
        .data_ready => |idx| {
            var buf: [1024]u8 = undefined;
            const n = s.read(idx, &buf);
            if (n > 0) _ = s.write(idx, buf[0..n]);
        },
        else => {},
    }
}

fn drainOutbound(ep: *SmallEndpoint, dst_mac: []const u8, tx_buf: []u8) void {
    var out_buf: [1600]u8 = undefined;
    while (ep.outboundCount() > 0) {
        const pkt = ep.readOutbound(&out_buf) orelse break;
        buildEthHdr(tx_buf, dst_mac[0..6].*, OUR_MAC, ETHERTYPE_IPV4);
        @memcpy(tx_buf[14 .. 14 + pkt.len], pkt);
        lan9118.send(tx_buf[0 .. 14 + pkt.len]);
    }
}

// --- Main server ---

var peer_mac: [6]u8 = BROADCAST_MAC;
var link_ep: SmallEndpoint = undefined;
var stack: StackT = undefined;

noinline fn runServer() noreturn {
    initSysTick();

    link_ep = SmallEndpoint.init();
    stack = StackT.init(&link_ep, OUR_IP);
    _ = stack.listen(7777, 4);

    lan9118.init();
    semihosting.puts("tinytcp: listening on 10.0.0.2:7777\n");

    // Gratuitous ARP
    var garp_buf: [42]u8 = undefined;
    buildEthHdr(&garp_buf, BROADCAST_MAC, OUR_MAC, ETHERTYPE_ARP);
    var ga = garp_buf[14..];
    writeU16Big(ga, 0, 1);
    writeU16Big(ga, 2, 0x0800);
    ga[4] = 6;
    ga[5] = 4;
    writeU16Big(ga, 6, 2);
    @memcpy(ga[8..14], &OUR_MAC);
    @memcpy(ga[14..18], &OUR_IP);
    @memcpy(ga[18..24], &BROADCAST_MAC);
    @memcpy(ga[24..28], &OUR_IP);
    lan9118.send(&garp_buf);

    var rx_buf: [1600]u8 = undefined;
    var tx_buf: [1600]u8 = undefined;

    while (true) {
        if (lan9118.recv(&rx_buf)) |frame| {
            if (frame.len < 14) continue;
            const etype = readU16Big(frame, 12);
            if (etype == ETHERTYPE_ARP) {
                if (handleArp(frame, &tx_buf)) |len| lan9118.send(tx_buf[0..len]);
            } else if (etype == ETHERTYPE_IPV4) {
                @memcpy(&peer_mac, frame[6..12]);
                handleIpv4(frame, &stack, &link_ep, &tx_buf);
            }
        }

        const poll_event = stack.poll(getTick());
        processEvent(&stack, poll_event);

        if (link_ep.outboundCount() > 0) {
            var timer_tx: [1600]u8 = undefined;
            drainOutbound(&link_ep, &peer_mac, &timer_tx);
        }
    }
}

// --- Entry point ---

export fn _start() noreturn {
    runServer();
}

pub const panic = std.debug.FullPanic(panicImpl);

fn panicImpl(msg: []const u8, _: ?usize) noreturn {
    _ = msg;
    semihosting.puts("PANIC\n");
    semihosting.exit();
}
