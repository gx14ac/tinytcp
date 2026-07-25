// TUN echo server: tinytcp on a real macOS utun device.
//
// Creates a utun, assigns an IP, and runs a TCP echo server.
// Events are dispatched through server.handle() — no manual
// stream tracking needed.
//
// Usage:
//   zig build
//   sudo ./zig-out/bin/tun-echo
//
// Test (in another terminal):
//   echo "hello" | nc 198.18.0.2 7777

const std = @import("std");
const posix = std.posix;
const tinytcp = @import("tinytcp");

const Stack = tinytcp.Stack(32);

// macOS utun constants
const PF_SYSTEM = 32;
const SYSPROTO_CONTROL = 2;
const AF_SYS_CONTROL = 2;
const UTUN_CONTROL_NAME = "com.apple.net.utun_control";
const CTLIOCGINFO: c_int = @bitCast(@as(c_uint, 0xc0644e03));

const ctl_info = extern struct {
    ctl_id: u32,
    ctl_name: [96]u8,
};

const sockaddr_ctl = extern struct {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [5]u32,
};

pub fn main() !void {
    const stdout = std.fs.File.stdout().deprecatedWriter();

    try stdout.print("tinytcp TUN echo server\n", .{});
    try stdout.print("=======================\n\n", .{});

    const tun_fd = try createUtun(10);
    defer posix.close(tun_fd);

    var ifname_buf: [32]u8 = undefined;
    const ifname = try getUtunName(tun_fd, &ifname_buf);
    try stdout.print("created {s}, assigned 198.18.0.1/24\n", .{ifname});

    try assignAddress(ifname);

    try stdout.print("tinytcp listening on 198.18.0.2:7777\n", .{});
    try stdout.print("test: echo hello | nc 198.18.0.2 7777\n\n", .{});

    // Set up tinytcp
    var link_ep = tinytcp.link.ChannelEndpoint.init();
    var stack = Stack.initWithSecret(
        &link_ep,
        .{ 198, 18, 0, 2 },
        .{ 0x42, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x11, 0x22, 0x33, 0x44 },
    );

    var server = Stack.Server.init(&stack);
    if (!server.listen(7777, 16)) {
        try stdout.print("error: failed to listen\n", .{});
        return;
    }

    // Event loop
    var read_buf: [2048]u8 = undefined;
    var out_buf: [2048]u8 = undefined;
    var poll_fds = [_]posix.pollfd{
        .{ .fd = tun_fd, .events = posix.POLL.IN, .revents = 0 },
    };

    var now_ms: u64 = 0;

    while (true) {
        const nready = try posix.poll(&poll_fds, 100);
        now_ms += 100;

        if (nready > 0 and (poll_fds[0].revents & posix.POLL.IN) != 0) {
            const n = try posix.read(tun_fd, &read_buf);
            if (n <= 4) continue;

            const af = std.mem.readInt(u32, read_buf[0..4], .big);
            if (af != 2) continue;

            const event = stack.injectPacket(now_ms, read_buf[4..n]);
            handleEvent(server.handle(event), &stdout);
        }

        const poll_event = stack.poll(now_ms);
        handleEvent(server.handle(poll_event), &stdout);

        while (link_ep.outboundCount() > 0) {
            const pkt = link_ep.readOutbound(out_buf[4..]) orelse break;
            std.mem.writeInt(u32, out_buf[0..4], 2, .big);
            _ = try posix.write(tun_fd, out_buf[0 .. 4 + pkt.len]);
        }
    }
}

fn handleEvent(event: Stack.ServerEvent, writer: anytype) void {
    switch (event) {
        .accepted => {
            writer.print("[+] accepted\n", .{}) catch {};
        },
        .data => |stream| {
            var buf: [4096]u8 = undefined;
            const n = stream.recv(&buf);
            if (n > 0) {
                writer.print("[<] {s}\n", .{buf[0..n]}) catch {};
                _ = stream.send(buf[0..n]);
            }
        },
        .closed => {
            writer.print("[-] closed\n", .{}) catch {};
        },
        .aborted, .none => {},
    }
}

fn createUtun(unit: u32) !posix.fd_t {
    const fd = try posix.socket(PF_SYSTEM, posix.SOCK.DGRAM, SYSPROTO_CONTROL);
    errdefer posix.close(fd);

    var info = ctl_info{ .ctl_id = 0, .ctl_name = undefined };
    @memset(&info.ctl_name, 0);
    @memcpy(info.ctl_name[0..UTUN_CONTROL_NAME.len], UTUN_CONTROL_NAME);

    const info_ptr: [*]u8 = @ptrCast(&info);
    const result = std.c.ioctl(fd, CTLIOCGINFO, @intFromPtr(info_ptr));
    if (result < 0) return error.IoctlFailed;

    var addr = sockaddr_ctl{
        .sc_len = @sizeOf(sockaddr_ctl),
        .sc_family = AF_SYS_CONTROL,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_id = info.ctl_id,
        .sc_unit = unit + 1,
        .sc_reserved = .{ 0, 0, 0, 0, 0 },
    };

    const addr_ptr: *const posix.sockaddr = @ptrCast(&addr);
    try posix.connect(fd, addr_ptr, @sizeOf(sockaddr_ctl));

    const O_NONBLOCK: usize = 0x0004;
    const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | O_NONBLOCK);

    return fd;
}

fn getUtunName(fd: posix.fd_t, buf: []u8) ![]const u8 {
    const UTUN_OPT_IFNAME = 2;
    var name_len: posix.socklen_t = @intCast(buf.len);
    const rc = std.c.getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, buf.ptr, &name_len);
    if (rc < 0) return error.GetSockOptFailed;
    const len = std.mem.indexOfScalar(u8, buf[0..name_len], 0) orelse name_len;
    return buf[0..len];
}

fn assignAddress(ifname: []const u8) !void {
    var cmd_buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "ifconfig {s} 198.18.0.1 198.18.0.1 netmask 255.255.255.0 up", .{ifname}) catch unreachable;

    var child = std.process.Child.init(
        &.{ "/bin/sh", "-c", cmd },
        std.heap.page_allocator,
    );
    child.spawn() catch return error.SpawnFailed;
    const term = child.wait() catch return error.WaitFailed;
    if (term.Exited != 0) return error.IfconfigFailed;

    var route_buf: [256]u8 = undefined;
    const route_cmd = std.fmt.bufPrint(&route_buf, "route add -net 198.18.0.0/24 -interface {s}", .{ifname}) catch unreachable;

    var route_child = std.process.Child.init(
        &.{ "/bin/sh", "-c", route_cmd },
        std.heap.page_allocator,
    );
    route_child.spawn() catch return error.SpawnFailed;
    _ = route_child.wait() catch return error.WaitFailed;
}
