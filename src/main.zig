const std = @import("std");
const gs2 = @import("gs2.zig");
const common = @import("common.zig");
const client = @import("client.zig");
const server = @import("server.zig");

pub const Client = client.Client;
pub const Server = server.Server;

pub const Credentials = server.Credentials;
pub const CredentialsLookup = server.CredentialsLookup;

pub const ClientSha1 = Client(std.crypto.hash.Sha1);
pub const ClientSha256 = Client(std.crypto.hash.sha2.Sha256);
pub const ClientSha512 = Client(std.crypto.hash.sha3.Sha3_512);

pub fn ServerSha1(comptime lookup: CredentialsLookup) type {
    return Server(std.crypto.hash.Sha1, lookup);
}

pub fn ServerSha256(comptime lookup: CredentialsLookup) type {
    return Server(std.crypto.hash.sha2.Sha256, lookup);
}

pub fn ServerSha512(comptime lookup: CredentialsLookup) type {
    return Server(std.crypto.hash.sha3.Sha3_512, lookup);
}

test "Test both client and server" {
    var alloc = std.testing.allocator;

    const credsLookup: server.CredentialsLookup = struct {
        fn creds(_: []const u8) anyerror!server.Credentials {
            return server.Credentials{
                .salt = &.{ 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118 },
                .iteration_count = 4096,
                .stored_key = &.{ 233, 217, 70, 96, 195, 157, 101, 195, 143, 186, 217, 28, 53, 143, 20, 218, 14, 239, 43, 214 },
                .server_key = &.{ 15, 224, 146, 88, 179, 172, 133, 43, 165, 2, 204, 98, 186, 144, 62, 170, 205, 191, 125, 49 },
            };
        }
    }.creds;

    var s = try ServerSha1(credsLookup).init(alloc, "3rfcNHYJY1ZVvWVs7j");
    defer s.deinit();

    var c = try ClientSha1.init(alloc, "user", "pencil", "fyko+d2lbbFgONRv9qkxdawL");
    defer c.deinit();

    const client_first = try c.clientFirst();
    defer alloc.free(client_first);

    const server_first = try s.serverFirst(client_first);
    defer alloc.free(server_first);

    const client_final = try c.clientFinal(server_first);
    defer alloc.free(client_final);

    const server_final = try s.serverFinal(client_final);
    defer alloc.free(server_final);

    try c.verify(server_final);
    try s.verify();
}

comptime {
    std.testing.refAllDecls(gs2);
    std.testing.refAllDecls(client);
    std.testing.refAllDecls(server);
}
