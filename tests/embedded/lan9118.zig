// SMSC LAN9118 Ethernet controller driver for QEMU MPS2-AN385.
//
// Minimal bare-metal driver supporting basic TX/RX of Ethernet frames.
// Reference: SMSC LAN9118 datasheet, QEMU hw/net/lan9118.c

const BASE: u32 = 0x40200000;

fn reg(offset: u32) *volatile u32 {
    return @ptrFromInt(BASE + offset);
}

// Register offsets
const RX_DATA_FIFO = 0x00;
const TX_DATA_FIFO = 0x20;
const RX_STATUS_FIFO = 0x40;
const INT_STS = 0x58;
const INT_EN = 0x5C;
const TX_CFG = 0x70;
const HW_CFG = 0x74;
const RX_FIFO_INF = 0x7C;
const MAC_CSR_CMD = 0xA4;
const MAC_CSR_DATA = 0xA8;

// MAC registers (indirect via MAC_CSR_CMD/DATA)
const MAC_CR = 1;
const MAC_ADDRH = 2;
const MAC_ADDRL = 3;

// Bit masks
const HW_CFG_SRST: u32 = 0x01;
const HW_CFG_MBO: u32 = 0x00100000;
const TX_CFG_ON: u32 = 0x02;
const MAC_CR_RXEN: u32 = 1 << 2;
const MAC_CR_TXEN: u32 = 1 << 3;
const MAC_CR_FDPX: u32 = 1 << 20;
const CSR_BUSY: u32 = 1 << 31;
const CSR_READ: u32 = 1 << 30;

fn spinWait(r: *volatile u32, mask: u32) void {
    var n: u32 = 0;
    while (r.* & mask != 0) : (n += 1) {
        if (n >= 100_000) break;
    }
}

fn macRead(addr: u32) u32 {
    reg(MAC_CSR_CMD).* = CSR_BUSY | CSR_READ | addr;
    spinWait(reg(MAC_CSR_CMD), CSR_BUSY);
    return reg(MAC_CSR_DATA).*;
}

fn macWrite(addr: u32, val: u32) void {
    reg(MAC_CSR_DATA).* = val;
    reg(MAC_CSR_CMD).* = CSR_BUSY | addr;
    spinWait(reg(MAC_CSR_CMD), CSR_BUSY);
}

pub const mac_addr = [6]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };

pub fn init() void {
    reg(HW_CFG).* = HW_CFG_SRST;
    spinWait(reg(HW_CFG), HW_CFG_SRST);

    reg(HW_CFG).* = HW_CFG_MBO;
    reg(INT_EN).* = 0;
    reg(INT_STS).* = 0xFFFFFFFF;

    macWrite(MAC_ADDRL, @as(u32, mac_addr[0]) |
        (@as(u32, mac_addr[1]) << 8) |
        (@as(u32, mac_addr[2]) << 16) |
        (@as(u32, mac_addr[3]) << 24));
    macWrite(MAC_ADDRH, @as(u32, mac_addr[4]) |
        (@as(u32, mac_addr[5]) << 8));

    macWrite(MAC_CR, MAC_CR_TXEN | MAC_CR_RXEN | MAC_CR_FDPX);
    reg(TX_CFG).* = TX_CFG_ON;
}

pub fn send(frame: []const u8) void {
    if (frame.len < 14 or frame.len > 1514) return;

    reg(TX_DATA_FIFO).* = (1 << 13) | (1 << 12) | @as(u32, @intCast(frame.len));
    reg(TX_DATA_FIFO).* = @as(u32, @intCast(frame.len));

    var i: usize = 0;
    while (i + 4 <= frame.len) : (i += 4) {
        reg(TX_DATA_FIFO).* = @as(u32, frame[i]) |
            (@as(u32, frame[i + 1]) << 8) |
            (@as(u32, frame[i + 2]) << 16) |
            (@as(u32, frame[i + 3]) << 24);
    }
    if (i < frame.len) {
        var word: u32 = 0;
        var j: u5 = 0;
        while (i < frame.len) : ({ i += 1; j += 1; }) {
            word |= @as(u32, frame[i]) << (@as(u5, j) * 8);
        }
        reg(TX_DATA_FIFO).* = word;
    }
}

pub fn recv(buf: []u8) ?[]u8 {
    if (reg(RX_FIFO_INF).* & 0xFFFF == 0) return null;

    const status = reg(RX_STATUS_FIFO).*;
    const pkt_len = (status >> 16) & 0x3FFF;
    if (pkt_len == 0) return null;

    const fifo_words = (pkt_len + 3) / 4;

    if (pkt_len > buf.len) {
        var k: usize = 0;
        while (k < fifo_words) : (k += 1) _ = reg(RX_DATA_FIFO).*;
        return null;
    }

    var i: usize = 0;
    var w: usize = 0;
    while (w < fifo_words) : (w += 1) {
        const word = reg(RX_DATA_FIFO).*;
        if (i < pkt_len) buf[i] = @truncate(word);
        if (i + 1 < pkt_len) buf[i + 1] = @truncate(word >> 8);
        if (i + 2 < pkt_len) buf[i + 2] = @truncate(word >> 16);
        if (i + 3 < pkt_len) buf[i + 3] = @truncate(word >> 24);
        i += 4;
    }

    return buf[0..pkt_len];
}
