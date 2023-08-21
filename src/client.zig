const std = @import("std");
const gs2 = @import("gs2.zig");

pub const Client = struct {
    alloc: std.mem.Allocator,
    username: []const u8,
    nonce: []const u8,

    pub fn init(alloc: std.mem.Allocator, username: []const u8, _: []const u8) !Client {
        return .{
            .alloc = alloc,
            .username = username,
            .nonce = try defaultNonceGenerator(alloc),
        };
    }

    pub fn client_first(self: Client) ![]const u8 {
        const c = ClientFirst{
            .username = self.user,
            .nonce = self.nonce,
        };

        return try c.serialize(self.alloc);
    }

    // pub fn client_final(self: Client, server_first: []const u8) ![]const u8 {

    // }
};

pub fn defaultNonceGenerator(alloc: std.mem.Allocator) ![]const u8 {
    var raw = try alloc.alloc(u8, 24);
    defer alloc.free(raw);

    std.crypto.random.bytes(raw);

    const base64 = std.base64.standard.Encoder;

    var nonce = try alloc.alloc(u8, base64.calcSize(raw.len));
    _ = base64.encode(nonce, raw);
    return nonce;
}

test "defaultNonceGenerator should work as expected" {
    const alloc = std.testing.allocator;

    const result = try defaultNonceGenerator(alloc);
    defer alloc.free(result);

    try std.testing.expectEqual(std.base64.standard.Encoder.calcSize(24), result.len);
}

pub const ClientFirst = struct {
    header: gs2.Header = .{ .cbind_flag = .{ .value = .{ .N = {} } } },
    reserved_mext: ?[]const u8 = null,
    username: []const u8,
    nonce: []const u8,
    extensions: ?[][]const u8 = null,

    pub fn serialize(self: ClientFirst, alloc: std.mem.Allocator) ![]const u8 {
        const header = try self.header.serialize(alloc);
        defer alloc.free(header);

        const reserved_mext = if (self.reserved_mext) |r| blk: {
            break :blk try std.mem.concat(alloc, u8, &.{ ",", r });
        } else "";

        // TODO: SASLPREP https://datatracker.ietf.org/doc/html/rfc4013
        const username = try gs2.encodeName(alloc, self.username);
        defer alloc.free(username);

        const extensions = if (self.extensions) |e| blk: {
            const joined = try std.mem.join(alloc, ",", e);
            defer alloc.free(joined);

            break :blk try std.mem.concat(alloc, u8, &.{ ",", joined });
        } else "";
        defer alloc.free(extensions);

        return try std.mem.concat(alloc, u8, &.{
            header,
            reserved_mext,
            "n=",
            username,
            ",",
            "r=",
            self.nonce,
            extensions,
        });
    }
};

test "ClientFirst should serialize correctly" {
    const alloc = std.testing.allocator;

    const client = ClientFirst{
        .username = "nefix",
        .nonce = "nonce",
    };
    const result = try client.serialize(alloc);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("n,,n=nefix,r=nonce", result);
}
