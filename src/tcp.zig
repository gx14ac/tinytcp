// High-level TCP API — Listener, Stream, and Server.
//
// All types are accessed via Stack: tinytcp.Stack(N) re-exports them as
// Stack.Server, Stack.Stream, Stack.Listener, Stack.ServerEvent.
//
// Usage (event-driven server):
//   const Stack = tinytcp.Stack(16);
//   var stack = Stack.init(&link, ip);
//   var server = Stack.Server.init(&stack);
//   server.listen(80, 16);
//
//   const event = stack.injectPacket(now, pkt);
//   switch (server.handle(event)) {
//       .accepted => |stream| { ... },
//       .data => |stream| { const n = stream.recv(&buf); ... },
//       .closed => { ... },
//       .none => {},
//   }
//
// Usage (simple / scripted):
//   var listener = Stack.Listener.init(&stack, 80, 8) orelse return;
//   var stream = Stack.Stream.connect(&stack, 0, addr, 80) orelse return;

const std = @import("std");

pub fn Tcp(comptime StackT: type) type {
    const Event = @import("full_stack.zig").Event;

    return struct {
        const max_conns = StackT.max_connections;

        pub const Listener = struct {
            stack: *StackT,
            port: u16,

            pub fn init(stack: *StackT, port: u16, backlog: u16) ?Listener {
                if (!stack.listen(port, backlog)) return null;
                return .{ .stack = stack, .port = port };
            }

            pub fn accept(self: *Listener) ?Stream {
                const idx = self.stack.accept() orelse return null;
                return .{ .stack = self.stack, .idx = idx };
            }
        };

        pub const Stream = struct {
            stack: *StackT,
            idx: u16,

            pub fn connect(stack: *StackT, now_ms: u64, addr: [4]u8, port: u16) ?Stream {
                const local_port = stack.allocEphemeralPort();
                const idx = stack.connect(now_ms, addr, port, local_port) orelse return null;
                return .{ .stack = stack, .idx = idx };
            }

            pub fn send(self: Stream, data: []const u8) usize {
                return self.stack.write(self.idx, data);
            }

            pub fn recv(self: Stream, buf: []u8) usize {
                return self.stack.read(self.idx, buf);
            }

            pub fn close(self: Stream) void {
                self.stack.close(self.idx);
            }

            pub fn state(self: Stream) ?@import("transport/tcp/connection.zig").State {
                return self.stack.connState(self.idx);
            }

            pub fn setNoDelay(self: Stream, enabled: bool) void {
                self.stack.setNoDelay(self.idx, enabled);
            }

            pub fn setKeepalive(self: Stream, enabled: bool) void {
                self.stack.setKeepalive(self.idx, enabled);
            }
        };

        pub const ServerEvent = union(enum) {
            none,
            accepted: Stream,
            data: Stream,
            closed: Stream,
            aborted: Stream,
        };

        pub const Server = struct {
            stack: *StackT,
            streams: [max_conns]bool = [_]bool{false} ** max_conns,

            pub fn init(stack: *StackT) Server {
                return .{ .stack = stack };
            }

            pub fn listen(self: *Server, port: u16, backlog: u16) bool {
                return self.stack.listen(port, backlog);
            }

            pub fn handle(self: *Server, event: Event) ServerEvent {
                switch (event) {
                    .accepted => {
                        // accept() can only be null if another consumer (e.g. a Listener on the
                        // same stack) already drained the backlog. Single-consumer is assumed.
                        const idx = self.stack.accept() orelse return .none;
                        self.streams[idx] = true;
                        return .{ .accepted = .{ .stack = self.stack, .idx = idx } };
                    },
                    .data_ready => |idx| {
                        if (idx < max_conns and self.streams[idx]) {
                            return .{ .data = .{ .stack = self.stack, .idx = idx } };
                        }
                        return .none;
                    },
                    .closed => |idx| {
                        if (idx < max_conns and self.streams[idx]) {
                            self.streams[idx] = false;
                            return .{ .closed = .{ .stack = self.stack, .idx = idx } };
                        }
                        return .none;
                    },
                    .aborted => |idx| {
                        if (idx < max_conns and self.streams[idx]) {
                            self.streams[idx] = false;
                            return .{ .aborted = .{ .stack = self.stack, .idx = idx } };
                        }
                        return .none;
                    },
                    // syn_pending only reaches a port registered with
                    // listenDeferred, and this Server registers plain ones.
                    .established, .udp_recv, .syn_pending, .none => return .none,
                }
            }

            pub fn injectPacket(self: *Server, now_ms: u64, raw: []const u8) ServerEvent {
                return self.handle(self.stack.injectPacket(now_ms, raw));
            }

            pub fn poll(self: *Server, now_ms: u64) ServerEvent {
                return self.handle(self.stack.poll(now_ms));
            }

            pub fn connect(self: *Server, now_ms: u64, addr: [4]u8, port: u16) ?Stream {
                const stream = Stream.connect(self.stack, now_ms, addr, port) orelse return null;
                self.streams[stream.idx] = true;
                return stream;
            }
        };
    };
}
