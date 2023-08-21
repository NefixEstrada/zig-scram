const std = @import("std");
const gs2 = @import("gs2.zig");
const client = @import("client.zig");
const server = @import("server.zig");

comptime {
    std.testing.refAllDecls(gs2);
    std.testing.refAllDecls(client);
    std.testing.refAllDecls(server);
}
