// TUN interop test server — Linux /dev/net/tun version.
//
// Creates tun0, assigns 10.99.0.2/24, runs tinytcp as echo server.
// Handles: TCP echo (port 7777), UDP echo (port 7778), ICMP ping reply.
//
// Built as part of `zig build tun-test`.

const std = @import("std");
const posix = std.posix;
const tinytcp = @import("tinytcp");

const FullStack = tinytcp.full_stack.FullStack(32);
const ChannelEndpoint = tinytcp.link.ChannelEndpoint;
const Event = tinytcp.full_stack.Event;

// Linux TUN constants
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
const TUNSETIFF: u32 = 0x400454ca;

const ifreq = extern struct {
    ifr_name: [16]u8,
    ifr_flags: u16,
    _pad: [22]u8,
};

pub fn main() !void {
    const log = std.debug.print;

    log("[tinytcp] Starting TUN test server (Linux)...\n", .{});

    // Step 1: Open /dev/net/tun
    const tun_fd = try posix.open("/dev/net/tun", .{ .ACCMODE = .RDWR }, 0);
    defer posix.close(tun_fd);

    // Step 2: Configure TUN device
    var ifr = std.mem.zeroes(ifreq);
    const tun_name = "tun0";
    @memcpy(ifr.ifr_name[0..tun_name.len], tun_name);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    const ioctl_result = std.c.ioctl(tun_fd, TUNSETIFF, @intFromPtr(&ifr));
    if (ioctl_result < 0) {
        log("[tinytcp] TUNSETIFF failed\n", .{});
        return error.IoctlFailed;
    }

    log("[tinytcp] Created TUN device: tun0\n", .{});

    // Step 3: Configure interface via ip commands
    try runCmd("ip addr add 10.99.0.1/24 dev tun0");
    try runCmd("ip link set tun0 up");
    try runCmd("ip route add 10.99.0.2/32 dev tun0");

    log("[tinytcp] Interface configured: 10.99.0.1/24\n", .{});
    log("[tinytcp] Stack IP: 10.99.0.2\n", .{});
    log("[tinytcp] TCP echo on port 7777, UDP echo on port 7778\n", .{});

    // Step 4: Initialize tinytcp stack
    var link_ep = ChannelEndpoint.init();
    var stack = FullStack.initWithSecret(
        &link_ep,
        .{ 10, 99, 0, 2 },
        .{ 0x42, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x11, 0x22, 0x33, 0x44 },
    );

    // Listen TCP 7777
    _ = stack.listen(7777, 16);

    // Bind UDP 7778
    const udp_ep = stack.udpBind(7778);

    // Step 5: Set TUN fd to non-blocking
    const flags = try posix.fcntl(tun_fd, posix.F.GETFL, 0);
    _ = try posix.fcntl(tun_fd, posix.F.SETFL, flags | @as(u32, 0x800)); // O_NONBLOCK

    log("[tinytcp] Entering event loop...\n", .{});

    // Step 6: Event loop
    var read_buf: [2048]u8 = undefined;
    var out_buf: [2048]u8 = undefined;

    var poll_fds = [_]posix.pollfd{
        .{ .fd = tun_fd, .events = posix.POLL.IN, .revents = 0 },
    };

    while (true) {
        const nready = try posix.poll(&poll_fds, 50);
        const now_ms: u64 = @intCast(std.time.milliTimestamp());

        if (nready > 0 and (poll_fds[0].revents & posix.POLL.IN) != 0) {
            // Read from TUN (Linux: raw IP packet, no header with IFF_NO_PI)
            const n = posix.read(tun_fd, &read_buf) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            if (n == 0) continue;

            const ip_pkt = read_buf[0..n];

            // Verify it's IPv4
            if (ip_pkt.len < 20) continue;
            if ((ip_pkt[0] >> 4) != 4) continue;

            // Check if it's ICMP echo request → respond directly
            if (ip_pkt[9] == 1) { // ICMP
                if (handleIcmpEcho(ip_pkt, &out_buf)) |reply_len| {
                    _ = posix.write(tun_fd, out_buf[0..reply_len]) catch {};
                    continue;
                }
            }

            // Inject into tinytcp
            const event = stack.injectPacket(now_ms, ip_pkt);
            handleEvent(&stack, event);
        }

        // Poll stack until no more events
        while (true) {
            const poll_event = stack.poll(now_ms);
            switch (poll_event) {
                .none => break,
                else => handleEvent(&stack, poll_event),
            }
        }

        // Handle UDP echo
        if (udp_ep) |ep| {
            if (stack.udpRecv(ep)) |dgram| {
                _ = stack.udpSendTo(ep, dgram.src_addr, dgram.src_port, dgram.data[0..dgram.len]);
            }
        }

        // Send outbound packets to TUN
        while (link_ep.outboundCount() > 0) {
            const pkt = link_ep.readOutbound(&out_buf) orelse break;
            _ = posix.write(tun_fd, out_buf[0..pkt.len]) catch {};
        }
    }
}

fn handleEvent(stack: anytype, event: Event) void {
    switch (event) {
        .accepted => {},
        .data_ready => |idx| {
            var buf: [8192]u8 = undefined;
            const n = stack.read(idx, &buf);
            if (n > 0) {
                _ = stack.write(idx, buf[0..n]);
            }
        },
        .established => {},
        .closed => {},
        .aborted => {},
        .udp_recv => {},
        .none => {},
    }
}

fn handleIcmpEcho(pkt: []const u8, out: []u8) ?usize {
    if (pkt.len < 28) return null; // 20 IP + 8 ICMP minimum

    const ihl: usize = @as(usize, pkt[0] & 0x0F) * 4;
    if (pkt.len < ihl + 8) return null;

    const icmp_offset = ihl;
    if (pkt[icmp_offset] != 8) return null; // Not echo request
    if (pkt[icmp_offset + 1] != 0) return null; // code != 0

    // Build echo reply
    const total_len = pkt.len;
    if (out.len < total_len) return null;

    @memcpy(out[0..total_len], pkt[0..total_len]);

    // Swap src/dst IP
    @memcpy(out[12..16], pkt[16..20]); // new src = old dst
    @memcpy(out[16..20], pkt[12..16]); // new dst = old src

    // Change ICMP type to 0 (echo reply)
    out[icmp_offset] = 0;

    // Recompute ICMP checksum
    out[icmp_offset + 2] = 0;
    out[icmp_offset + 3] = 0;
    var cksum: u32 = 0;
    var i: usize = icmp_offset;
    while (i + 1 < total_len) : (i += 2) {
        cksum += @as(u32, out[i]) << 8 | @as(u32, out[i + 1]);
    }
    if (i < total_len) {
        cksum += @as(u32, out[i]) << 8;
    }
    while (cksum >> 16 != 0) {
        cksum = (cksum & 0xffff) + (cksum >> 16);
    }
    const sum = ~@as(u16, @intCast(cksum & 0xffff));
    out[icmp_offset + 2] = @intCast(sum >> 8);
    out[icmp_offset + 3] = @intCast(sum & 0xff);

    // Recompute IP header checksum
    out[10] = 0;
    out[11] = 0;
    var ip_cksum: u32 = 0;
    i = 0;
    while (i + 1 < ihl) : (i += 2) {
        ip_cksum += @as(u32, out[i]) << 8 | @as(u32, out[i + 1]);
    }
    while (ip_cksum >> 16 != 0) {
        ip_cksum = (ip_cksum & 0xffff) + (ip_cksum >> 16);
    }
    const ip_sum = ~@as(u16, @intCast(ip_cksum & 0xffff));
    out[10] = @intCast(ip_sum >> 8);
    out[11] = @intCast(ip_sum & 0xff);

    return total_len;
}

fn runCmd(cmd: []const u8) !void {
    var child = std.process.Child.init(
        &.{ "/bin/sh", "-c", cmd },
        std.heap.page_allocator,
    );
    child.spawn() catch return error.SpawnFailed;
    const term = child.wait() catch return error.WaitFailed;
    switch (term) {
        .Exited => |code| {
            if (code != 0) return error.CmdFailed;
        },
        else => return error.CmdFailed,
    }
}
