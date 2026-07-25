// tinytcp — Sans-IO userspace TCP/IP stack.
//
// Zero-allocation data path, comptime polymorphism, single-threaded event loop design.

// === Primary API ===

const full_stack_mod = @import("full_stack.zig");

pub const Stack = full_stack_mod.FullStack;

const DefaultStack = Stack(16);
pub const Server = DefaultStack.Server;
pub const ServerEvent = DefaultStack.ServerEvent;
pub const Listener = DefaultStack.Listener;
pub const Stream = DefaultStack.Stream;

pub fn init(link_ep: *link.ChannelEndpoint, local_ip: [4]u8) DefaultStack {
    return DefaultStack.init(link_ep, local_ip);
}

pub fn initWithSecret(link_ep: *link.ChannelEndpoint, local_ip: [4]u8, secret: [16]u8) DefaultStack {
    return DefaultStack.initWithSecret(link_ep, local_ip, secret);
}

pub const tcp = @import("tcp.zig");
pub const full_stack = full_stack_mod;
pub const config = @import("config.zig");
pub const link = @import("link.zig");

// === Protocol Modules ===

pub const header = @import("header.zig");
pub const checksum = @import("checksum.zig");
pub const arp = @import("arp.zig");
pub const ndp = @import("ndp.zig");
pub const slaac = @import("slaac.zig");
pub const dhcp = @import("dhcp.zig");
pub const dns = @import("dns/handler.zig");
pub const igmp = @import("igmp.zig");
pub const mld = @import("mld.zig");
pub const ip_reassembly = @import("ip_reassembly.zig");
pub const ipv6_frag = @import("ipv6_frag.zig");
pub const route = @import("route.zig");

// === Advanced / Internal ===

pub const socket = @import("socket.zig");
pub const packet_buf = @import("packet_buf.zig");
pub const pool = @import("pool.zig");
pub const timer_wheel = @import("timer_wheel.zig");
pub const conntrack = @import("conntrack.zig");
pub const packet_filter = @import("packet_filter.zig");
pub const ip_forward = @import("ip_forward.zig");
pub const zero_copy = @import("zero_copy.zig");
pub const gro = @import("link/gro.zig");
pub const gso = @import("link/gso.zig");
pub const raw_endpoint = @import("transport/raw/endpoint.zig");
pub const tcp_connection = @import("transport/tcp/connection.zig");
pub const tcp_options = @import("transport/tcp/options.zig");
pub const udp_endpoint = @import("transport/udp/endpoint.zig");

test {
    _ = tcp;
    _ = full_stack;
    _ = config;
    _ = link;
    _ = header;
    _ = checksum;
    _ = arp;
    _ = ndp;
    _ = slaac;
    _ = dhcp;
    _ = dns;
    _ = igmp;
    _ = mld;
    _ = ip_reassembly;
    _ = ipv6_frag;
    _ = route;
    _ = socket;
    _ = packet_buf;
    _ = pool;
    _ = timer_wheel;
    _ = conntrack;
    _ = packet_filter;
    _ = ip_forward;
    _ = zero_copy;
    _ = gro;
    _ = gso;
    _ = raw_endpoint;
    _ = tcp_connection;
    _ = tcp_options;
    _ = udp_endpoint;
    _ = @import("demux.zig");
    _ = @import("stack.zig");
    _ = @import("forward/flow_table.zig");
    _ = @import("forward/forwarder.zig");
    _ = @import("tcp_stack.zig");
    _ = @import("isn.zig");
    _ = @import("syn_cookie.zig");
    _ = @import("integration.zig");
    _ = @import("transport/tcp/endpoint.zig");
    _ = @import("transport/tcp/rtt.zig");
    _ = @import("transport/tcp/congestion.zig");
    _ = @import("transport/tcp/timer.zig");
    _ = @import("transport/tcp/sender.zig");
    _ = @import("transport/tcp/receiver.zig");
    _ = @import("transport/tcp/cubic.zig");
    _ = @import("transport/tcp/bbr.zig");
    _ = @import("e2e_test.zig");
    _ = @import("tcp_api_test.zig");
}
