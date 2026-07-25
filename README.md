# tinytcp

Sans-IO userspace TCP/IP stack in Zig. Zero-allocation data path, comptime generics, no libc dependency.

Designed for embedding in VPN tunnels (WireGuard), WASM runtimes, bare-metal firmware, and anywhere you need a full TCP/IP stack without OS sockets.

## Features

- Full TCP (3-way handshake, retransmission, congestion control, keepalive, FIN/RST)
- IPv4 and IPv6 dual-stack
- ICMP echo reply, ICMPv6
- UDP endpoints
- IP fragment reassembly
- SYN cookies (DoS protection)
- ARP, NDP, SLAAC, DHCPv4
- DNS intercept
- Comptime-parameterized: tune buffer sizes, connection count, and features at compile time
- Runs on Linux, macOS, Windows, bare-metal ARM (Cortex-M3), and anywhere Zig compiles

## Quick Start

```zig
const tinytcp = @import("tinytcp");

const Stack = tinytcp.Stack(16);

var link = tinytcp.link.ChannelEndpoint.init();
var stack = Stack.init(&link, .{ 10, 0, 0, 1 });

// Create a server — handles event dispatch automatically
var server = Stack.Server.init(&stack);
_ = server.listen(80, 8);

// Event loop
while (true) {
    const event = stack.injectPacket(now_ms, pkt);
    switch (server.handle(event)) {
        .accepted => |stream| {
            // new connection ready
            _ = stream;
        },
        .data => |stream| {
            var buf: [4096]u8 = undefined;
            const n = stream.recv(&buf);
            _ = stream.send(buf[0..n]); // echo
        },
        .closed => {},
        .aborted, .none => {},
    }
    _ = stack.poll(now_ms);
}
```

## Build

Requires Zig 0.15.x.

```sh
zig build          # build library
zig build test     # run unit tests
zig build echo     # run minimal example
```

## Example

`examples/echo.zig` — TCP echo with Server API:

```zig
const std = @import("std");
const tinytcp = @import("tinytcp");

const Stack = tinytcp.Stack(4);

pub fn main() !void {
    var link_a = tinytcp.link.ChannelEndpoint.init();
    var link_b = tinytcp.link.ChannelEndpoint.init();

    var server_stack = Stack.init(&link_a, .{ 10, 0, 0, 1 });
    var client_stack = Stack.init(&link_b, .{ 10, 0, 0, 2 });

    // Server side
    var server = Stack.Server.init(&server_stack);
    _ = server.listen(80, 4);

    // Client side
    var stream = Stack.Stream.connect(&client_stack, 0, .{ 10, 0, 0, 1 }, 80) orelse return;
    _ = client_stack.poll(0);

    // Pump until handshake
    var t: u64 = 1;
    while (t < 50) : (t += 1) {
        pumpToServer(&link_b, &server_stack, &server, t);
        pumpRaw(&link_a, &client_stack, t);
    }

    // Send and deliver
    _ = stream.send("hello tinytcp");
    _ = client_stack.poll(t);
    t += 1;
    pumpToServer(&link_b, &server_stack, &server, t);
}

fn pumpToServer(src: anytype, dst: *Stack, srv: *Stack.Server, now: u64) void {
    var buf: [1600]u8 = undefined;
    while (src.readOutbound(&buf)) |pkt| {
        const event = dst.injectPacket(now, pkt);
        switch (srv.handle(event)) {
            .accepted => std.debug.print("accepted\n", .{}),
            .data => |s| {
                var rbuf: [64]u8 = undefined;
                const n = s.recv(&rbuf);
                std.debug.print("received: {s}\n", .{rbuf[0..n]});
            },
            .closed, .aborted, .none => {},
        }
    }
    _ = dst.poll(now);
}

fn pumpRaw(src: anytype, dst: *Stack, now: u64) void {
    var buf: [1600]u8 = undefined;
    while (src.readOutbound(&buf)) |pkt| { _ = dst.injectPacket(now, pkt); }
    _ = dst.poll(now);
}
```

## Architecture

```
Application
    |
    v
+--------------------------+
|  FullStack               |  <-- comptime FullStack(max_conns)
|  +- TCP connections      |
|  +- UDP endpoints        |
|  +- ICMP handler         |
|  +- IPv4/IPv6 dispatch   |
|  +- ARP / NDP / SLAAC    |
|  +- Fragment reassembly  |
+----------+---------------+
           |  injectPacket() / poll()
           v
+--------------------------+
|  LinkEndpoint (trait)    |  <-- plug in your own transport
|  e.g. ChannelEndpoint,   |
|       TUN fd, WireGuard  |
+--------------------------+
```

Sans-IO design: no sockets, no threads, no allocator. The caller drives time (`now_ms`) and I/O (inject inbound packets, extract outbound packets). This makes it trivial to embed in event loops, WASM, bare-metal firmware, or test harnesses.

## API Layers

| Layer | Type | Use case |
|-------|------|----------|
| `Stack.Server` | Event-driven | Real applications with event loops |
| `Stack.Listener` / `Stack.Stream` | Scripted | Simple programs, tests |
| `Stack` raw methods | Direct | Maximum control, custom event handling |

## Embedded

tinytcp compiles for `thumb-freestanding-eabi` (Cortex-M3) with `ReleaseSmall`. Use `Config.embedded_minimal` to reduce per-connection RAM to ~4KB:

```zig
const cfg = tinytcp.config.Config.embedded_minimal;
var stack = tinytcp.full_stack.FullStackWith(4, cfg).init(&link, ip);
```

## Configuration

All buffer sizes are comptime parameters via `Config`:

| Parameter | Default | Embedded Minimal |
|-----------|---------|------------------|
| send_buf_size | 32 KB | 1 KB |
| recv_buf_size | 64 KB | 2 KB |
| max_ooo_segments | 32 | 4 |
| max_retx_queue | 128 | 16 |
| max_reasm_datagram | 8192 | 1500 |
| MSS | 1460 | 536 |

## Roadmap

- [ ] Per-destination Path MTU Discovery cache + aging
- [ ] NAT module (masquerade, port pool, incremental checksum update)
- [ ] mDNS / DNS-SD (multicast DNS for local service discovery)
- [ ] DHCP server mode (for gateway / AP use cases)
- [ ] Inbound TCP/UDP checksum verification (currently trusts lower layer integrity)
- [ ] TLS record layer integration point

## Related Projects

- [runetale](https://github.com/runetale) — Mesh VPN using tinytcp as the userspace network stack

## License

MIT
