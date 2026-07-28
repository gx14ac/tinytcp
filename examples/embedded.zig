// Embedded TCP server — minimal RAM footprint for bare-metal / WASM.
//
// Demonstrates:
//   - Config.embedded_minimal (~4KB per connection)
//   - ChannelEndpointWith(4, 256) for tiny link buffers
//   - Static RAM usage fully known at compile time
//
// This example runs on any target including freestanding (Cortex-M, RISC-V, WASM).
// No allocator, no libc, no OS.

const std = @import("std");
const tinytcp = @import("tinytcp");

const Config = tinytcp.config.Config;
const SmallLink = tinytcp.link.ChannelEndpointWith(4, 512);
const Stack = tinytcp.full_stack.FullStackFull(2, Config.embedded_minimal, SmallLink);

pub fn main() !void {
    std.debug.print("tinytcp embedded example\n", .{});
    std.debug.print("========================\n\n", .{});
    std.debug.print("Config: embedded_minimal\n", .{});
    std.debug.print("  send_buf:  {d} bytes/conn\n", .{Config.embedded_minimal.send_buf_size});
    std.debug.print("  recv_buf:  {d} bytes/conn\n", .{Config.embedded_minimal.recv_buf_size});
    std.debug.print("  MSS:       {d}\n", .{Config.embedded_minimal.default_mss});
    std.debug.print("  RAM/conn:  ~{d} bytes\n", .{Config.embedded_minimal.perConnBytes()});
    std.debug.print("  max_conns: 2\n", .{});
    std.debug.print("  Stack size: {d} bytes (includes hash table + alignment padding)\n", .{@sizeOf(Stack)});
    std.debug.print("  Effective data per conn: ~{d} bytes\n\n", .{Config.embedded_minimal.perConnBytes()});

    // Two embedded stacks talking to each other
    var link_a = SmallLink.init();
    var link_b = SmallLink.init();

    var server_stack = Stack.init(&link_a, .{ 192, 168, 1, 1 });
    var client_stack = Stack.init(&link_b, .{ 192, 168, 1, 2 });

    _ = server_stack.listen(80, 2);

    // Client connects
    const idx = client_stack.connect(0, .{ 192, 168, 1, 1 }, 80, 5000) orelse {
        std.debug.print("ERROR: connect failed\n", .{});
        return;
    };
    _ = client_stack.poll(0);

    // Pump handshake
    var t: u64 = 1;
    while (t < 30) : (t += 1) {
        pumpBidi(&link_a, &link_b, &server_stack, &client_stack, t);
    }

    // Client sends data
    const msg = "hello from embedded";
    _ = client_stack.write(idx, msg);
    _ = client_stack.poll(t);
    t += 1;

    pumpBidi(&link_a, &link_b, &server_stack, &client_stack, t);

    // Server reads
    const srv_idx = server_stack.accept() orelse 0;
    var buf: [64]u8 = undefined;
    const n = server_stack.read(srv_idx, &buf);
    if (n > 0) {
        std.debug.print("server received: \"{s}\"\n", .{buf[0..n]});
    }

    std.debug.print("\nembedded example complete.\n", .{});
}

fn pumpBidi(link_a: *SmallLink, link_b: *SmallLink, stack_a: *Stack, stack_b: *Stack, now: u64) void {
    var buf: [512]u8 = undefined;
    // B → A (client outbound → server inbound)
    while (link_b.readOutbound(&buf)) |pkt| {
        _ = stack_a.injectPacket(now, pkt);
    }
    _ = stack_a.poll(now);
    // A → B (server outbound → client inbound)
    while (link_a.readOutbound(&buf)) |pkt| {
        _ = stack_b.injectPacket(now, pkt);
    }
    _ = stack_b.poll(now);
}
