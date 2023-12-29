const std = @import("std");
const common = @import("common.zig");

pub const Header = struct {
    nonstd_flag: bool = false,
    cbind_flag: CbindFlag,
    authzid: ?[]const u8 = null,

    pub fn serialize(self: Header, alloc: std.mem.Allocator) ![]const u8 {
        const cbind_flag = try self.cbind_flag.serialize(alloc);
        defer alloc.free(cbind_flag);

        const authzid = if (self.authzid) |a| blk: {
            break :blk try encodeName(alloc, a);
        } else "";
        defer alloc.free(authzid);

        return std.mem.concat(alloc, u8, &.{
            if (self.nonstd_flag) "F," else "",
            cbind_flag,
            ",",
            if (self.authzid) |_| "a=" else "",
            if (self.authzid) |_| authzid else "",
            ",",
        });
    }

    pub fn deserialize(parts: *std.mem.SplitIterator(u8, .scalar)) !Header {
        // Non standard flag
        var part = parts.next();
        if (part == null) return error.HeaderInvalid;
        const nonstd_flag = if (std.mem.eql(u8, part.?, "F")) true else false;

        // Channel bind flag
        part = if (nonstd_flag) parts.next() else part;
        if (part == null) return error.HeaderInvalid;
        const cbind_flag = try CbindFlag.deserialize(part.?);

        // Authz ID
        part = parts.next();
        if (part == null) return error.HeaderInvalid;
        const authzid = common.deserializeOptionalPart("a", part) catch return error.HeaderInvalid;

        return Header{
            .nonstd_flag = nonstd_flag,
            .cbind_flag = cbind_flag,
            .authzid = authzid,
        };
    }
};

test "Header should serialize correctly" {
    const alloc = std.testing.allocator;

    var h = Header{
        .cbind_flag = .{
            .N = {},
        },
    };
    const result1 = try h.serialize(alloc);
    defer alloc.free(result1);
    try std.testing.expectEqualStrings("n,,", result1);

    h.authzid = "hello";
    const result2 = try h.serialize(alloc);
    defer alloc.free(result2);
    try std.testing.expectEqualStrings("n,a=hello,", result2);
}

test "Header should deserialize correctly" {
    var parts = std.mem.splitScalar(u8, "n,a=hello,", ',');
    const header = try Header.deserialize(&parts);

    try std.testing.expectEqualDeep(Header{
        .cbind_flag = .{ .N = {} },
        .authzid = "hello",
    }, header);
}

pub const CbindFlag = union(enum) {
    P: []const u8,
    N: void,
    Y: void,

    pub fn serialize(self: CbindFlag, alloc: std.mem.Allocator) ![]const u8 {
        switch (self) {
            .P => |p| {
                const name = try encodeName(alloc, p);
                defer alloc.free(name);

                return try std.mem.concat(alloc, u8, &.{ "p=", name });
            },
            .N => return try alloc.dupe(u8, "n"),
            .Y => return try alloc.dupe(u8, "y"),
        }
    }

    pub fn deserialize(msg: []const u8) !CbindFlag {
        switch (msg.len) {
            0 => return error.CbindInvalid,
            1 => {
                switch (msg[0]) {
                    'n' => return .{ .N = {} },
                    'y' => return .{ .Y = {} },
                    else => return error.CbindFlagInvalid,
                }
            },
            else => {
                var parts = std.mem.splitScalar(u8, msg, '=');
                if (!std.mem.eql(u8, parts.first(), "p")) return error.CbindFlagInvalid;

                const name = parts.next();
                if (name == null) return error.CbindFlagInvalid;

                if (parts.peek() != null) return error.CbindFlagInvalid;

                return .{ .P = name.? };
            },
        }
    }
};

test "CbindFlag should serialize correctly" {
    const alloc = std.testing.allocator;

    var c = CbindFlag{ .P = "hello" };

    const result1 = try c.serialize(alloc);
    defer alloc.free(result1);
    try std.testing.expectEqualStrings("p=hello", result1);

    c = .{ .N = {} };
    const result2 = try c.serialize(alloc);
    defer alloc.free(result2);
    try std.testing.expectEqualStrings("n", result2);

    c = .{ .Y = {} };
    const result3 = try c.serialize(alloc);
    defer alloc.free(result3);
    try std.testing.expectEqualStrings("y", result3);
}

test "CbindFlag should deserialize correctly" {
    try std.testing.expectEqual(CbindFlag{ .N = {} }, try CbindFlag.deserialize("n"));
    try std.testing.expectEqual(CbindFlag{ .Y = {} }, try CbindFlag.deserialize("y"));
    try std.testing.expectEqualDeep(CbindFlag{ .P = "hello" }, try CbindFlag.deserialize("p=hello"));
    try std.testing.expectError(error.CbindFlagInvalid, CbindFlag.deserialize("p=hello=my=friend:D"));
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
