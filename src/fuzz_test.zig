// Fuzz tests for tinytcp header parsers.
// Ensures no crashes on arbitrary byte input.

const std = @import("std");
const testing = std.testing;
const header = @import("header.zig");

// Fuzz: IPv4 header parsing must not crash.
test "fuzz: ipv4 parse no crash" {
    try testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) anyerror!void {
            _ = header.ipv4.Header.parse(input) catch return;
        }
    }.testOne, .{});
}

// Fuzz: IPv6 header parsing must not crash.
test "fuzz: ipv6 parse no crash" {
    try testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) anyerror!void {
            _ = header.ipv6.Header.parse(input) catch return;
        }
    }.testOne, .{});
}

// Fuzz: TCP header parsing must not crash.
test "fuzz: tcp parse no crash" {
    try testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) anyerror!void {
            _ = header.tcp.Header.parse(input) catch return;
        }
    }.testOne, .{});
}

// Fuzz: UDP header parsing must not crash.
test "fuzz: udp parse no crash" {
    try testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) anyerror!void {
            _ = header.udp.Header.parse(input) catch return;
        }
    }.testOne, .{});
}

// Fuzz: ICMP header parsing must not crash.
test "fuzz: icmp parse no crash" {
    try testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) anyerror!void {
            _ = header.icmp.Header.parse(input) catch return;
        }
    }.testOne, .{});
}
