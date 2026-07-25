// Bare-metal smoke test for tinytcp on ARM Cortex-M (QEMU semihosting).
//
// Runs a FullStack E2E test (TCP handshake + data transfer) entirely in-memory
// using a small ChannelEndpoint. Reports pass/fail via ARM semihosting.
//
// Usage:
//   zig build embedded-smoke
//   qemu-system-arm -machine mps2-an385 -nographic -semihosting \
//     -kernel zig-out/bin/embedded-smoke

const std = @import("std");
const tinytcp = @import("tinytcp");
const config_mod = tinytcp.config;
const full_stack_mod = tinytcp.full_stack;
const link_mod = tinytcp.link;
const tcp_header_mod = tinytcp.header.tcp;
const ipv4_header_mod = tinytcp.header.ipv4;

const Config = config_mod.Config;
const SmallEndpoint = link_mod.ChannelEndpointWith(4, 256);
const StackT = full_stack_mod.FullStackFull(1, Config.embedded_minimal, SmallEndpoint);

const semihosting = struct {
    const SYS_WRITE0: u32 = 0x04;
    const SYS_EXIT: u32 = 0x18;

    fn call(reason: u32, arg: u32) u32 {
        return asm volatile ("bkpt 0xab"
            : [ret] "={r0}" (-> u32),
            : [r0] "{r0}" (reason),
              [r1] "{r1}" (arg),
        );
    }

    fn puts(msg: [*:0]const u8) void {
        _ = call(SYS_WRITE0, @intFromPtr(msg));
    }

    fn exitSuccess() noreturn {
        _ = call(SYS_EXIT, 0x20026); // ADP_Stopped_ApplicationExit
        unreachable;
    }

    fn exitFailure() noreturn {
        _ = call(SYS_EXIT, 0x20023); // ADP_Stopped_ApplicationError
        unreachable;
    }
};

fn buildTcpPacket(
    src_addr: [4]u8,
    src_port: u16,
    dst_addr: [4]u8,
    dst_port: u16,
    seq: u32,
    ack_val: u32,
    flags: tcp_header_mod.Flags,
    window: u16,
    payload: []const u8,
    out: []u8,
) usize {
    const ip_hlen: usize = 20;
    const tcp_hlen: usize = 20;
    const total: usize = ip_hlen + tcp_hlen + payload.len;

    var ip = ipv4_header_mod.MutableHeader.init(out[0..ip_hlen]) catch return 0;
    ip.setTotalLen(@intCast(total));
    ip.setTtl(64);
    ip.setProtocol(.tcp);
    ip.setSrcAddr(src_addr);
    ip.setDstAddr(dst_addr);
    ip.computeChecksum();

    var tcp = tcp_header_mod.MutableHeader.init(out[ip_hlen .. ip_hlen + tcp_hlen]) catch return 0;
    tcp.setSrcPort(src_port);
    tcp.setDstPort(dst_port);
    tcp.setSeqNum(seq);
    tcp.setAckNum(ack_val);
    tcp.setFlags(flags);
    tcp.setWindowSize(window);

    if (payload.len > 0) {
        for (0..payload.len) |i| {
            out[ip_hlen + tcp_hlen + i] = payload[i];
        }
    }
    tcp.computeChecksumIpv4(src_addr, dst_addr, out[ip_hlen..total]);

    return total;
}

var link_ep: SmallEndpoint = undefined;
var stack: StackT = undefined;

noinline fn runTest() bool {
    link_ep = SmallEndpoint.init();
    stack = StackT.init(&link_ep, .{ 10, 0, 0, 1 });
    _ = stack.listen(80, 1);

    // Client sends SYN
    var pkt_buf: [256]u8 = undefined;
    const syn_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        9000,
        .{ 10, 0, 0, 1 },
        80,
        1000,
        0,
        .{ .syn = true },
        2048,
        &.{},
        &pkt_buf,
    );
    if (syn_len == 0) return false;

    const ev1 = stack.injectPacket(0, pkt_buf[0..syn_len]);
    switch (ev1) {
        .accepted => {},
        else => return false,
    }

    // Extract SYN+ACK
    var out_buf: [256]u8 = undefined;
    const syn_ack_raw = link_ep.readOutbound(&out_buf) orelse return false;

    // Parse SYN+ACK to get server ISN
    const ip_hdr = ipv4_header_mod.Header.parse(syn_ack_raw) catch return false;
    const ip_payload = ip_hdr.payload(syn_ack_raw);
    const tcp_hdr = tcp_header_mod.Header.parse(ip_payload) catch return false;
    const server_isn = tcp_hdr.seqNum();
    const flags = tcp_hdr.flags();
    if (!flags.syn or !flags.ack) return false;

    // Complete handshake: send ACK
    const ack_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        9000,
        .{ 10, 0, 0, 1 },
        80,
        1001,
        server_isn + 1,
        .{ .ack = true },
        2048,
        &.{},
        &pkt_buf,
    );
    if (ack_len == 0) return false;

    const ev2 = stack.injectPacket(10, pkt_buf[0..ack_len]);
    switch (ev2) {
        .accepted, .established => {},
        else => return false,
    }

    // Send data from client
    const data_len = buildTcpPacket(
        .{ 10, 0, 0, 2 },
        9000,
        .{ 10, 0, 0, 1 },
        80,
        1001,
        server_isn + 1,
        .{ .ack = true, .psh = true },
        2048,
        "OK",
        &pkt_buf,
    );
    if (data_len == 0) return false;

    const ev3 = stack.injectPacket(20, pkt_buf[0..data_len]);
    switch (ev3) {
        .data_ready, .accepted => {},
        else => return false,
    }

    // Read data back
    var read_buf: [16]u8 = undefined;
    const n = stack.read(0, &read_buf);
    if (n != 2) return false;
    if (read_buf[0] != 'O' or read_buf[1] != 'K') return false;

    return true;
}

export fn _start() noreturn {
    @call(.auto, main, .{});
}

fn main() noreturn {
    semihosting.puts("tinytcp embedded smoke test\n");

    if (runTest()) {
        semihosting.puts("PASS: TCP handshake + data transfer\n");
        semihosting.exitSuccess();
    } else {
        semihosting.puts("FAIL: test did not complete\n");
        semihosting.exitFailure();
    }
}

pub const panic = std.debug.FullPanic(panicImpl);

fn panicImpl(msg: []const u8, _: ?usize) noreturn {
    _ = msg;
    semihosting.puts("PANIC\n");
    semihosting.exitFailure();
}
