const std = @import("std");

pub const Header = struct {
    nonstd_flag: bool = false,
    cbind_flag: CbindFlag,
    authzid: ?Authzid = null,

    pub fn serialize(self: Header, alloc: std.mem.Allocator) ![]const u8 {
        const cbind_flag = try self.cbind_flag.serialize(alloc);
        defer alloc.free(cbind_flag);

        const authzid = if (self.authzid) |a| blk: {
            break :blk try a.serialize(alloc);
        } else "";
        defer alloc.free(authzid);

        return std.mem.concat(alloc, u8, &.{
            if (self.nonstd_flag) "F," else "",
            cbind_flag,
            ",",
            authzid,
            ",",
        });
    }
};

test "Header should serialize correctly" {
    const alloc = std.testing.allocator;

    var h = Header{
        .cbind_flag = .{
            .value = .{
                .N = {},
            },
        },
    };
    const result1 = try h.serialize(alloc);
    defer alloc.free(result1);
    try std.testing.expectEqualStrings("n,,", result1);

    h.authzid = .{ .value = "hello" };
    const result2 = try h.serialize(alloc);
    defer alloc.free(result2);
    try std.testing.expectEqualStrings("n,a=hello,", result2);
}

pub const CbindFlag = struct {
    value: union(enum) {
        P: []const u8,
        N: void,
        Y: void,
    },

    pub fn serialize(self: CbindFlag, alloc: std.mem.Allocator) ![]const u8 {
        switch (self.value) {
            .P => |p| {
                const name = try encodeName(alloc, p);
                defer alloc.free(name);

                return try std.mem.concat(alloc, u8, &.{ "p=", name });
            },
            .N => return try alloc.dupe(u8, "n"),
            .Y => return try alloc.dupe(u8, "y"),
        }
    }
};

test "CbindFlag should serialize correctly" {
    const alloc = std.testing.allocator;

    var c = CbindFlag{ .value = .{ .P = "hello" } };

    const result1 = try c.serialize(alloc);
    defer alloc.free(result1);
    try std.testing.expectEqualStrings("p=hello", result1);

    c.value = .{ .N = {} };
    const result2 = try c.serialize(alloc);
    defer alloc.free(result2);
    try std.testing.expectEqualStrings("n", result2);

    c.value = .{ .Y = {} };
    const result3 = try c.serialize(alloc);
    defer alloc.free(result3);
    try std.testing.expectEqualStrings("y", result3);
}

pub const Authzid = struct {
    value: []const u8,

    pub fn serialize(self: Authzid, alloc: std.mem.Allocator) ![]const u8 {
        const value = try encodeName(alloc, self.value);
        defer alloc.free(value);

        return try std.mem.concat(alloc, u8, &.{ "a=", value });
    }
};

test "Authzid should get serialize correctly" {
    const a = Authzid{ .value = "hello" };
    const result = try a.serialize(std.testing.allocator);
    defer std.testing.allocator.free(result);

    try std.testing.expectEqualStrings("a=hello", result);
}

pub fn encodeName(alloc: std.mem.Allocator, name: []const u8) ![]const u8 {
    const name1 = try std.mem.replaceOwned(u8, alloc, name, "=", "=3D");
    defer alloc.free(name1);

    return try std.mem.replaceOwned(u8, alloc, name1, ",", "=2C");
}

test "encodeName should encode the characters correctly" {
    const alloc = std.testing.allocator;

    const result1 = try encodeName(alloc, "hello");
    defer alloc.free(result1);
    try std.testing.expectEqualStrings("hello", result1);

    const result2 = try encodeName(alloc, "És veraç!");
    defer alloc.free(result2);
    try std.testing.expectEqualStrings("És veraç!", result2);

    const result3 = try encodeName(alloc, "this, is, a, comma");
    defer alloc.free(result3);
    try std.testing.expectEqualStrings("this=2C is=2C a=2C comma", result3);

    const result4 = try encodeName(alloc, "this = this other");
    defer alloc.free(result4);
    try std.testing.expectEqualStrings("this =3D this other", result4);

    const result5 = try encodeName(alloc, "no way, this = this other");
    defer alloc.free(result5);
    try std.testing.expectEqualStrings("no way=2C this =3D this other", result5);
}
