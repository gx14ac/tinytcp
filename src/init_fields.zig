// Copyright (c) 2026 gx14ac
// SPDX-License-Identifier: Apache-2.0

// Setting a large struct to its defaults without a copy of them in the
// binary.
//
// `p.* = .{}` builds the defaults as one constant and copies it in. When
// every default is zero or undefined the constant is left out and the copy
// becomes a memset, but a single field with another default puts the whole
// value in the binary: an MSS of 1460 in each pending SYN, a next header of
// 59 in each v6 fragment flow. A stack's reassembly slots, pending SYNs and
// flow table come to about 180 KB that way.
//
// Writing each field from its own default keeps the defaults where they
// are, in the type's declaration, and costs no more than the fields with
// another default. A large struct field is set the same way, one field at a
// time, and so is each element of a large array of structs.

const std = @import("std");

/// Set every field of `p.*` to its default, as `p.* = .{}` does, or to the
/// value `values` gives it: `initFields(T, p, .{ .link = l })` is
/// `p.* = .{ .link = l }`. A field `values` leaves out must have a default.
pub fn initFields(comptime T: type, p: *T, values: anytype) void {
    inline for (@typeInfo(T).@"struct".fields) |f| {
        if (@hasField(@TypeOf(values), f.name)) {
            @field(p, f.name) = @field(values, f.name);
        } else if (comptime nests(f.type)) {
            initFields(f.type, &@field(p, f.name), .{});
        } else if (comptime nestsEach(f.type)) {
            const E = @typeInfo(f.type).array.child;
            for (&@field(p, f.name)) |*e| initFields(E, e, .{});
        } else {
            @field(p, f.name) = f.defaultValue() orelse
                @compileError(@typeName(T) ++ "." ++ f.name ++ " has no default");
        }
    }
}

/// A field this large is set a part at a time. Below it, a constant of the
/// field's own size costs less than the code to set each part.
const nest_min_size = 1024;

/// Whether a field of type F is set field by field, from F's own defaults.
/// That is the same as its default only when the field's default is F{}:
/// `inner: F = .{}`. One written otherwise is a difference that
/// `expectSameAs` reports.
fn nests(comptime F: type) bool {
    return @sizeOf(F) >= nest_min_size and allDefaulted(F);
}

/// Whether a field of type F, an array of structs, is set an element at a
/// time, each from the element type's own defaults. That is the same as its
/// default only when the default is `[_]E{.{}} ** n`.
fn nestsEach(comptime F: type) bool {
    const a = switch (@typeInfo(F)) {
        .array => |a| a,
        else => return false,
    };
    return @sizeOf(F) >= nest_min_size and allDefaulted(a.child);
}

fn allDefaulted(comptime F: type) bool {
    const info = switch (@typeInfo(F)) {
        .@"struct" => |s| s,
        else => return false,
    };
    if (info.layout == .@"packed") return false;
    for (info.fields) |g| {
        if (g.is_comptime or g.default_value_ptr == null) return false;
    }
    return true;
}

/// Whether `initFields(T, p, values)` gives `want`, field by field, leaving
/// out `undefined_fields`: the fields whose default is undefined, which hold
/// whatever they held. A field inside a large struct field is named by its
/// path, `reassembler.slots[].buf`; `[]` stands for every element of an
/// array. `want` should start from bytes of 0x5A, as `got` does here, so
/// that a default initFields failed to write is a difference. Call this
/// from a test in a Debug build, where `.{}` writes zeros to an undefined
/// field and initFields writes 0xAA, so an undefined field missing from the
/// list is reported too.
pub fn expectSameAs(comptime T: type, want: *const T, values: anytype, comptime undefined_fields: []const []const u8) !void {
    const got = try std.testing.allocator.create(T);
    defer std.testing.allocator.destroy(got);
    @memset(std.mem.asBytes(got), 0x5A);
    initFields(T, got, values);
    try expectSameFields(T, want, got, undefined_fields);
}

/// Whether `got` is `want`, compared the way expectSameAs does: for a
/// function that sets its fields with initFields and more besides.
pub fn expectSameFields(comptime T: type, want: *const T, got: *const T, comptime undefined_fields: []const []const u8) !void {
    // Every difference is printed before failing, so one run names all of
    // the undefined fields a list is missing.
    if (countDifferences(T, want, got, "", undefined_fields) > 0) return error.TestExpectedEqual;
}

fn countDifferences(
    comptime T: type,
    want: *const T,
    got: *const T,
    comptime prefix: []const u8,
    comptime undefined_fields: []const []const u8,
) usize {
    @setEvalBranchQuota(100_000);
    var n: usize = 0;
    inline for (@typeInfo(T).@"struct".fields) |f| {
        const path = prefix ++ f.name;
        const skip = comptime for (undefined_fields) |name| {
            if (std.mem.eql(u8, name, path)) break true;
        } else false;
        if (skip) {
            // Left out.
        } else if (comptime nests(f.type)) {
            n += countDifferences(f.type, &@field(want, f.name), &@field(got, f.name), path ++ ".", undefined_fields);
        } else if (comptime nestsEach(f.type)) {
            const E = @typeInfo(f.type).array.child;
            for (&@field(want, f.name), &@field(got, f.name)) |*w, *g| {
                const d = countDifferences(E, w, g, path ++ "[].", undefined_fields);
                n += d;
                // One element names what is wrong in all of them.
                if (d > 0) break;
            }
        } else if (!sameValue(f.type, &@field(want, f.name), &@field(got, f.name))) {
            std.debug.print("{s} differs from its default\n", .{path});
            n += 1;
        }
    }
    return n;
}

/// std.meta.eql, or the bytes for a value with a union in it, whose tag an
/// undefined default may leave as no member at all. Both sides come from
/// the same default, so the same bytes are the same value.
fn sameValue(comptime V: type, a: *const V, b: *const V) bool {
    if (comptime hasUnion(V)) return std.mem.eql(u8, std.mem.asBytes(a), std.mem.asBytes(b));
    return std.meta.eql(a.*, b.*);
}

fn hasUnion(comptime V: type) bool {
    return switch (@typeInfo(V)) {
        .@"union" => true,
        .@"struct" => |s| for (s.fields) |g| {
            if (hasUnion(g.type)) break true;
        } else false,
        .array => |a| hasUnion(a.child),
        .optional => |o| hasUnion(o.child),
        else => false,
    };
}

test "initFields sets every field to its default" {
    const S = struct {
        port: u16 = 443,
        count: u8 = 0,
        scratch: [16]u8 = undefined,
        inner: struct { on: bool = true, n: i32 = -1 } = .{},
    };
    const want = try std.testing.allocator.create(S);
    defer std.testing.allocator.destroy(want);
    @memset(std.mem.asBytes(want), 0x5A);
    want.* = .{};
    try expectSameAs(S, want, .{}, &.{"scratch"});
}

test "initFields sets a large struct field one field at a time" {
    const Inner = struct {
        mss: u16 = 1460,
        buf: [2048]u8 = undefined,
        len: u16 = 0,
    };
    const S = struct {
        inner: Inner = .{},
        ready: bool = false,
    };
    var s: S = undefined;
    initFields(S, &s, .{});
    try std.testing.expectEqual(@as(u16, 1460), s.inner.mss);
    try std.testing.expectEqual(@as(u16, 0), s.inner.len);
    try std.testing.expect(!s.ready);
}

test "initFields sets each element of a large array of structs" {
    const Slot = struct {
        next_header: u8 = 59,
        buf: [256]u8 = undefined,
        active: bool = false,
    };
    const S = struct {
        slots: [8]Slot = [_]Slot{.{}} ** 8,
        count: usize = 0,
    };
    const want = try std.testing.allocator.create(S);
    defer std.testing.allocator.destroy(want);
    @memset(std.mem.asBytes(want), 0x5A);
    want.* = .{};
    try expectSameAs(S, want, .{}, &.{"slots[].buf"});

    var s: S = undefined;
    initFields(S, &s, .{ .count = 3 });
    for (s.slots) |slot| {
        try std.testing.expectEqual(@as(u8, 59), slot.next_header);
        try std.testing.expect(!slot.active);
    }
    try std.testing.expectEqual(@as(usize, 3), s.count);
}

test "expectSameAs reports a default initFields does not give" {
    // An array whose default is not every element at its own default.
    const Slot = struct { gen: u32 = 0, buf: [300]u8 = .{0} ** 300 };
    const S = struct {
        slots: [4]Slot = .{ .{ .gen = 1 }, .{}, .{}, .{} },
    };
    const want = try std.testing.allocator.create(S);
    defer std.testing.allocator.destroy(want);
    want.* = .{};
    try std.testing.expectError(error.TestExpectedEqual, expectSameAs(S, want, .{}, &.{}));
}
