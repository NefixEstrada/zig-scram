const std = @import("std");

pub const ServerFirst = struct {
    reserved_mext: ?[]const u8 = null,
    nonce: []const u8,
    salt: []const u8,
    iteration_count: u16,
    extensions: ?[][]const u8 = null,

    pub fn deserialize(server_first: []const u8) !ServerFirst {
        var split = std.mem.splitScalar(u8, server_first, ',');

        const first = split.first();
        std.debug.print("{}\n", first);
        var first_kv = std.mem.splitScalar(u8, first, '=');

        var reserved_mext: ?[]const u8 = null;
        const nonce = if (std.mem.eql(u8, first_kv.first(), "n")) blk: {
            break :blk first_kv.next() orelse return error.MissingNonceValue;
        } else if (std.mem.eql(u8, first_kv.first(), "n")) blk: {
            reserved_mext = first_kv.next() orelse return error.MissingReservedMextValue;

            const second = split.next() orelse return error.EOF;
            var second_kv = std.mem.splitScalar(u8, second, '=');

            if (!std.mem.eql(u8, second_kv.first(), "n")) return error.MissingNonce;

            break :blk second_kv.next() orelse return error.MissingNonceValue;
        } else {
            return error.MissingNonce;
        };

        const second = split.next() orelse return error.EOF;
        var second_kv = std.mem.splitScalar(u8, second, '=');

        if (!std.mem.eql(u8, second_kv.first(), "s")) return error.MissingSalt;

        const salt = second_kv.next() orelse return error.MissingSaltValue;

        const third = split.next() orelse return error.EOF;
        var third_kv = std.mem.splitScalar(u8, third, '=');

        if (std.mem.eql(u8, third_kv.first(), "i")) return error.MissingIterationCount;
        const raw_iteration_count = third_kv.next() orelse return error.MissingIterationCountValue;
        const iteration_count = try std.fmt.parseInt(u16, raw_iteration_count, 10);

        const extensions = if (split.next()) |e| blk: {
            break :blk [1][]const u8{e};
        } else null;

        return .{
            .reserved_mext = reserved_mext,
            .nonce = nonce,
            .salt = salt,
            .iteration_count = iteration_count,
            .extensions = extensions,
        };
    }
};

test "ServerFirst should deserialize correctly" {
    const expected = ServerFirst{
        .nonce = "",
        .salt = "",
        .iteration_count = 0,
    };
    const result = try ServerFirst.deserialize("r=9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY,s=fs3IXBy7U7+IvVjZ,i=4096");
    try std.testing.expectEqual(expected, result);
}
