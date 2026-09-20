// Comptime configuration for tinytcp stack.
//
// All buffer sizes, queue depths, and feature knobs are parameterized here.
// Default values match the existing hardcoded constants (backwards-compatible).
// Embedded targets can pass a minimal config to reduce RAM footprint.

pub const Config = struct {
    /// TCP send buffer size per connection (bytes).
    send_buf_size: usize = 32768,

    /// TCP receive buffer size per connection (bytes).
    recv_buf_size: usize = 65536,

    /// Maximum out-of-order segments tracked per connection.
    max_ooo_segments: usize = 32,

    /// Maximum segments in the retransmission queue.
    max_retx_queue: usize = 128,

    /// Enable receive window auto-tuning.
    auto_tune_enabled: bool = true,

    /// Auto-tune: minimum buffer target (bytes).
    auto_tune_min_buf: usize = 65536,

    /// Auto-tune: maximum buffer target (bytes).
    auto_tune_max_buf: usize = 512 * 1024,

    /// Default MSS (Maximum Segment Size).
    default_mss: u16 = 1460,

    /// Enable Nagle algorithm by default.
    nagle_enabled: bool = true,

    /// Maximum reassembled datagram size (IPv4 fragment reassembly buffer per slot).
    max_reasm_datagram: usize = 8192,

    /// Ports the stack can listen on at once. A listen holds its slot until
    /// unlisten gives it back, so a caller that opens a listener per
    /// destination port needs room for every port it will serve at once.
    max_listen_ports: usize = 8,

    /// UDP endpoints open at once. Unlike listen ports these come back on
    /// their own, when the endpoint is closed.
    max_udp_endpoints: usize = 16,

    /// Minimal embedded profile: ~4KB per connection.
    pub const embedded_minimal = Config{
        .send_buf_size = 1024,
        .recv_buf_size = 2048,
        .max_ooo_segments = 4,
        .max_retx_queue = 16,
        .auto_tune_enabled = false,
        .auto_tune_min_buf = 2048,
        .auto_tune_max_buf = 2048,
        .default_mss = 536,
        .nagle_enabled = true,
        .max_reasm_datagram = 1500,
    };

    /// Small embedded profile: ~16KB per connection.
    pub const embedded_small = Config{
        .send_buf_size = 4096,
        .recv_buf_size = 8192,
        .max_ooo_segments = 8,
        .max_retx_queue = 32,
        .auto_tune_enabled = false,
        .auto_tune_min_buf = 8192,
        .auto_tune_max_buf = 8192,
        .default_mss = 1460,
        .nagle_enabled = true,
    };

    /// Default profile: matches existing hardcoded values.
    pub const default = Config{};

    /// Approximate RAM per connection (send_buf + recv_buf + OOO + retx overhead).
    pub fn perConnBytes(comptime self: Config) usize {
        const OooSegment = @import("transport/tcp/receiver.zig").OooSegment;
        const RetxSegment = @import("transport/tcp/sender.zig").RetxSegment;
        const ooo_size = self.max_ooo_segments * @sizeOf(OooSegment);
        const retx_size = self.max_retx_queue * @sizeOf(RetxSegment);
        return self.send_buf_size + self.recv_buf_size + ooo_size + retx_size;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = @import("std").testing;

test "Config: default matches existing hardcoded values" {
    const cfg = Config.default;
    try testing.expectEqual(@as(usize, 32768), cfg.send_buf_size);
    try testing.expectEqual(@as(usize, 65536), cfg.recv_buf_size);
    try testing.expectEqual(@as(usize, 32), cfg.max_ooo_segments);
    try testing.expectEqual(@as(usize, 128), cfg.max_retx_queue);
    try testing.expect(cfg.auto_tune_enabled);
}

test "Config: embedded_minimal reduces RAM" {
    const cfg = Config.embedded_minimal;
    try testing.expectEqual(@as(usize, 1024), cfg.send_buf_size);
    try testing.expectEqual(@as(usize, 2048), cfg.recv_buf_size);
    try testing.expectEqual(@as(usize, 4), cfg.max_ooo_segments);
    try testing.expectEqual(@as(usize, 16), cfg.max_retx_queue);
    try testing.expect(!cfg.auto_tune_enabled);
}

test "Config: perConnBytes calculation" {
    const default_bytes = Config.default.perConnBytes();
    const minimal_bytes = Config.embedded_minimal.perConnBytes();
    try testing.expect(default_bytes > 90_000);
    try testing.expect(minimal_bytes < 10_000);
    try testing.expect(minimal_bytes < default_bytes);
}
