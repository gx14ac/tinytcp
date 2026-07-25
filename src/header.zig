// Wire-format header parsers for IP/TCP/UDP/ICMP.
// All parsers work on borrowed byte slices — zero allocation, zero copy.

pub const ipv4 = @import("header/ipv4.zig");
pub const ipv6 = @import("header/ipv6.zig");
pub const tcp = @import("header/tcp.zig");
pub const udp = @import("header/udp.zig");
pub const icmp = @import("header/icmp.zig");

test {
    _ = ipv4;
    _ = ipv6;
    _ = tcp;
    _ = udp;
    _ = icmp;
}
