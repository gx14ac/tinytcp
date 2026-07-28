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

var link = tinytcp.link.ChannelEndpoint.init();
var stack = tinytcp.init(&link, .{ 10, 0, 0, 1 });

var server = tinytcp.Server.init(&stack);
_ = server.listen(80, 8);

// Event loop
while (true) {
    handleEvent(server.injectPacket(now_ms, pkt));
    handleEvent(server.poll(now_ms));
}

fn handleEvent(event: tinytcp.ServerEvent) void {
    switch (event) {
        .data => |stream| {
            var buf: [4096]u8 = undefined;
            const n = stream.recv(&buf);
            _ = stream.send(buf[0..n]); // echo
        },
        .accepted, .closed, .aborted, .none => {},
    }
}
```

For custom connection limits, use `tinytcp.Stack(N)` directly:

```zig
const Stack = tinytcp.Stack(64);
var stack = Stack.init(&link, ip);
var server = Stack.Server.init(&stack);
```

## Build

Requires Zig 0.15.x.

```sh
zig build                # build library
zig build test           # run unit tests
zig build echo           # TCP echo (Server API)
zig build embedded-example   # minimal RAM footprint demo
zig build packet-filter  # firewall / middlebox emulation
zig build time-travel    # deterministic protocol testing
zig build tun-echo       # real TUN device (macOS, requires sudo)
```

## Example

`examples/echo.zig` — TCP echo with Server API:

```zig
const std = @import("std");
const tinytcp = @import("tinytcp");

pub fn main() !void {
    var link_a = tinytcp.link.ChannelEndpoint.init();
    var link_b = tinytcp.link.ChannelEndpoint.init();

    var server_stack = tinytcp.init(&link_a, .{ 10, 0, 0, 1 });
    var client_stack = tinytcp.init(&link_b, .{ 10, 0, 0, 2 });

    var server = tinytcp.Server.init(&server_stack);
    _ = server.listen(80, 4);

    var stream = tinytcp.Stream.connect(&client_stack, 0, .{ 10, 0, 0, 1 }, 80) orelse return;
    _ = client_stack.poll(0);

    // Pump until handshake
    var t: u64 = 1;
    while (t < 50) : (t += 1) {
        pump(&link_b, &server, t);
        pumpRaw(&link_a, &client_stack, t);
    }

    // Send and deliver
    _ = stream.send("hello tinytcp");
    _ = client_stack.poll(t);
    t += 1;
    pump(&link_b, &server, t);
}

fn pump(src: anytype, srv: anytype, now: u64) void {
    var buf: [1600]u8 = undefined;
    while (src.readOutbound(&buf)) |pkt| {
        switch (srv.injectPacket(now, pkt)) {
            .accepted => std.debug.print("accepted\n", .{}),
            .data => |s| {
                var rbuf: [64]u8 = undefined;
                const n = s.recv(&rbuf);
                std.debug.print("received: {s}\n", .{rbuf[0..n]});
            },
            .closed, .aborted, .none => {},
        }
    }
    _ = srv.poll(now);
}

fn pumpRaw(src: anytype, dst: anytype, now: u64) void {
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

## Use Cases

**VPN / Overlay Networks** — Embed a full TCP/IP stack inside WireGuard or custom tunnels. Sans-IO design fits naturally into VPN event loops without threading or callbacks.

**Network Appliance Emulation** — Build virtual firewalls, NAT gateways, load balancers, or IDS systems. Inspect and filter packets between stacks with zero overhead. See `examples/packet_filter.zig`.

**Protocol Testing & Fuzzing** — Time is a parameter, not a wall clock. Freeze time, inject crafted packets, verify exact state transitions, reproduce race conditions deterministically. See `examples/time_travel.zig`.

**Embedded / Bare-metal** — Runs on Cortex-M3 with ~4KB RAM per connection. No allocator, no libc, no OS. Comptime generics let you tune buffer sizes for your target. See `examples/embedded.zig`.

**WASM Runtimes** — No syscalls, no libc, no threads. Compile to WASM and drive the stack from JavaScript or any host runtime.

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

## License

MIT
