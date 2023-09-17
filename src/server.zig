const std = @import("std");
const gs2 = @import("gs2.zig");
const common = @import("common.zig");
const client = @import("client.zig");

pub const CredentialsLookup = fn (username: []const u8) anyerror!Credentials;

pub const Credentials = struct {
    salt: []const u8,
    iteration_count: u16,
    stored_key: []const u8,
    server_key: []const u8,
};

pub fn Server(comptime Hash: type, comptime lookup: CredentialsLookup) type {
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);

    return struct {
        const Self = @This();
        const base64 = std.base64.standard.Encoder;

        alloc: std.mem.Allocator,
        nonce: []const u8,
        nonce_generated: bool,

        credentials: ?Credentials = null,
        client_first_bare: ?[]const u8 = null,
        server_first: ?[]const u8 = null,
        err: ?ServerError = null,

        pub fn init(alloc: std.mem.Allocator, nonce: ?[]const u8) !Self {
            return .{
                .alloc = alloc,
                .nonce = nonce orelse try common.defaultNonceGenerator(alloc),
                .nonce_generated = nonce == null,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.nonce_generated) self.alloc.free(self.nonce);
            if (self.client_first_bare) |c| self.alloc.free(c);
        }

        pub fn serverFirst(self: *Self, msg: []const u8) anyerror![]const u8 {
            const client_first = try client.ClientFirst.deserialize(msg);
            self.client_first_bare = try client_first.serializeBare(self.alloc);

            self.credentials = try lookup(client_first.username);

            var salt = try self.alloc.alloc(u8, base64.calcSize(self.credentials.?.salt.len));
            defer self.alloc.free(salt);
            _ = base64.encode(salt, self.credentials.?.salt);

            self.nonce = try std.mem.concat(self.alloc, u8, &.{ client_first.nonce, self.nonce });
            self.nonce_generated = true;

            var rsp = ServerFirst{
                .nonce = self.nonce,
                .salt = salt,
                .iteration_count = self.credentials.?.iteration_count,
            };

            self.server_first = try rsp.serialize(self.alloc);
            return self.server_first.?;
        }

        pub fn serverFinal(self: *Self, msg: []const u8) ![]const u8 {
            var client_final = try client.ClientFinal.deserialize(self.alloc, msg);
            defer client_final.deinit(self.alloc);

            if (!std.mem.eql(u8, client_final.nonce, self.nonce)) {
                self.err = .@"other-error";
                const err = ServerFinal{ .err = self.err.? };
                return try err.serialize(self.alloc);
            }

            const without_proof = try client_final.serializeWithoutProof(self.alloc);
            defer self.alloc.free(without_proof);

            var auth_message = try std.mem.concat(self.alloc, u8, &.{
                self.client_first_bare.?,
                ",",
                self.server_first.?,
                ",",
                without_proof,
            });
            defer self.alloc.free(auth_message);

            var client_signature: [Hmac.mac_length]u8 = undefined;
            Hmac.create(&client_signature, auth_message, self.credentials.?.stored_key);

            var client_key = try self.alloc.dupe(u8, client_final.proof);
            defer self.alloc.free(client_key);

            for (client_signature, 0..) |value, i| {
                client_key[i] ^= value;
            }

            var stored_key: [Hash.digest_length]u8 = undefined;
            Hash.hash(client_key, &stored_key, .{});

            if (!std.mem.eql(u8, &stored_key, self.credentials.?.stored_key)) {
                self.err = .@"invalid-proof";
                const err = ServerFinal{ .err = self.err.? };
                return try err.serialize(self.alloc);
            }
            var server_signature: [Hmac.mac_length]u8 = undefined;
            Hmac.create(&server_signature, auth_message, self.credentials.?.server_key);

            const server_final = ServerFinal{ .signature = &server_signature };
            return try server_final.serialize(self.alloc);
        }

        pub fn verify(self: *Self) !void {
            if (self.err) |_| @panic("AAAAAAAA");
        }
    };
}

test "Server should send the server first message correctly" {
    var allocator = std.testing.allocator;

    // Taken from https://wiki.xmpp.org/web/SASL_Authentication_and_SCRAM
    const credsLookup: CredentialsLookup = struct {
        fn creds(_: []const u8) anyerror!Credentials {
            return Credentials{
                .salt = &.{ 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118 },
                .iteration_count = 4096,
                .stored_key = "stored",
                .server_key = "server",
            };
        }
    }.creds;

    var s = try Server(std.crypto.hash.Sha1, credsLookup).init(allocator, "c12b3985bbd4a8e6f814b422ab766573");
    defer s.deinit();

    const result = try s.serverFirst("n,,n=romeo,r=6d442b5d9e51a740f369e3dcecf3178e");
    defer allocator.free(result);

    try std.testing.expectEqualStrings("r=6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573,s=QSXCR+Q6sek8bf92,i=4096", result);
}

test "Server should send the server final message correctly" {
    var allocator = std.testing.allocator;

    const credsLookup: CredentialsLookup = struct {
        fn creds(_: []const u8) anyerror!Credentials {
            return Credentials{
                .salt = &.{ 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118 },
                .iteration_count = 4096,
                .stored_key = &.{ 233, 217, 70, 96, 195, 157, 101, 195, 143, 186, 217, 28, 53, 143, 20, 218, 14, 239, 43, 214 },
                .server_key = &.{ 15, 224, 146, 88, 179, 172, 133, 43, 165, 2, 204, 98, 186, 144, 62, 170, 205, 191, 125, 49 },
            };
        }
    }.creds;

    var s = try Server(std.crypto.hash.Sha1, credsLookup).init(allocator, "3rfcNHYJY1ZVvWVs7j");
    defer s.deinit();

    // Taken from https://wiki.xmpp.org/web/SASL_Authentication_and_SCRAM
    const server_first = try s.serverFirst("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL");
    defer allocator.free(server_first);

    const result = try s.serverFinal("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=");
    defer allocator.free(result);

    try std.testing.expectEqualStrings("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=", result);
}

pub const ServerFirst = struct {
    const base64Decoder = std.base64.standard.Decoder;

    reserved_mext: ?[]const u8 = null,
    nonce: []const u8,
    salt: []const u8,
    iteration_count: u32,
    extensions: ?[][]const u8 = null,

    pub fn deinit(self: *ServerFirst, alloc: std.mem.Allocator) void {
        alloc.free(self.salt);
    }

    pub fn serialize(self: *ServerFirst, alloc: std.mem.Allocator) ![]const u8 {
        const iter = try std.fmt.allocPrint(alloc, "{d}", .{self.iteration_count});
        defer alloc.free(iter);

        // TODO: Salt base64 should be here

        // TODO: Extensions

        return try std.mem.concat(alloc, u8, &.{
            if (self.reserved_mext) |_| "m=" else "",
            if (self.reserved_mext) |r| r else "",
            if (self.reserved_mext) |_| "," else "",
            "r=",
            self.nonce,
            ",",
            "s=",
            self.salt,
            ",",
            "i=",
            iter,
        });
    }

    pub fn deserialize(alloc: std.mem.Allocator, server_first: []const u8) !ServerFirst {
        var parts = std.mem.splitScalar(u8, server_first, ',');

        // Reserved mext
        var part: ?[]const u8 = parts.first();
        const reserved_mext = common.deserializeOptionalPart("m", part) catch return error.ServerFirstInvalid;

        // Nonce
        part = if (reserved_mext != null) parts.next() else part;
        if (part == null) return error.ServerFirstInvalid;
        const nonce = common.deserializePart("r", part.?) catch return error.ServerFirstInvalid;

        // Salt
        part = parts.next();
        if (part == null) return error.ServerFirstInvalid;
        const salt = blk: {
            const raw_salt = common.deserializePart("s", part.?) catch return error.ServerFirstInvalid;

            var s = try alloc.alloc(u8, try base64Decoder.calcSizeForSlice(raw_salt));
            try base64Decoder.decode(s, raw_salt);

            break :blk s;
        };

        // Iteration count
        part = parts.next();
        if (part == null) return error.ServerFirstInvalid;
        const iteration_count = std.fmt.parseInt(
            u32,
            common.deserializePart("i", part.?) catch return error.ServerFirstInvalid,
            10,
        ) catch return error.ServerFirstInvalid;

        // TODO: Extensions

        return .{
            .reserved_mext = reserved_mext,
            .nonce = nonce,
            .salt = salt,
            .iteration_count = iteration_count,
            .extensions = null,
        };
    }
};

test "ServerFirst should serialize correctly" {
    var allocator = std.testing.allocator;

    var s = ServerFirst{
        .nonce = "9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY",
        .salt = "fs3IXBy7U7+IvVjZ",
        .iteration_count = 4096,
    };

    const result = try s.serialize(allocator);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("r=9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY,s=fs3IXBy7U7+IvVjZ,i=4096", result);
}

test "ServerFirst should deserialize correctly" {
    var alloc = std.testing.allocator;

    const expected = ServerFirst{
        .nonce = "9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY",
        .salt = &.{ 65, 37, 194, 71, 228, 58, 177, 233, 60, 109, 255, 118 },
        .iteration_count = 4096,
    };
    var result = try ServerFirst.deserialize(alloc, "r=9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY,s=QSXCR+Q6sek8bf92,i=4096");
    defer result.deinit(alloc);

    try std.testing.expectEqualDeep(expected, result);
}

pub const ServerError = enum {
    @"invalid-encoding",
    @"extensions-not-supported",
    @"invalid-proof",
    @"channel-bindings-dont-match",
    @"server-does-support-channel-binding",
    @"channel-binding-not-supported",
    @"unsupported-channel-binding-type",
    @"unknown-user",
    @"invalid-username-encoding",
    @"no-resources",
    @"other-error",
    @"server-error-value-ext",
};

// TODO: Extensions
pub const ServerFinal = union(enum) {
    const base64Encoder = std.base64.standard.Encoder;
    const base64Decoder = std.base64.standard.Decoder;

    err: ServerError,
    signature: []const u8,

    pub fn deinit(self: *ServerFinal, alloc: std.mem.Allocator) void {
        alloc.free(self.signature);
    }

    pub fn serialize(self: ServerFinal, alloc: std.mem.Allocator) ![]const u8 {
        switch (self) {
            .err => |e| {
                return try std.mem.concat(alloc, u8, &.{
                    "e=",
                    @tagName(e),
                });
            },
            .signature => |s| {
                var signature = try alloc.alloc(u8, base64Encoder.calcSize(s.len));
                defer alloc.free(signature);
                _ = base64Encoder.encode(signature, s);

                return try std.mem.concat(alloc, u8, &.{
                    "v=",
                    signature,
                });
            },
        }
    }

    pub fn deserialize(alloc: std.mem.Allocator, server_final: []const u8) !ServerFinal {
        var parts = std.mem.splitScalar(u8, server_final, ',');

        // Error
        var part: []const u8 = parts.first();
        const err = common.deserializeOptionalPart("e", part) catch return error.ServerFinalInvalid;
        if (err) |_| return ServerFinal{
            .err = .@"no-resources",
        };

        // Signature
        const raw_signature = common.deserializePart("v", part) catch return error.ServerFinalInvalid;
        var signature = try alloc.alloc(u8, try base64Decoder.calcSizeForSlice(raw_signature));
        _ = try base64Decoder.decode(signature, raw_signature);
        return ServerFinal{
            .signature = signature,
        };
    }
};

test "ServerFinal should serialize correctly" {
    var alloc = std.testing.allocator;

    var err = ServerFinal{ .err = .@"other-error" };
    const err_result = try err.serialize(alloc);
    defer alloc.free(err_result);

    try std.testing.expectEqualStrings("e=other-error", err_result);

    var verifier = ServerFinal{ .signature = "holi :)!!" };
    const verifier_result = try verifier.serialize(alloc);
    defer alloc.free(verifier_result);

    try std.testing.expectEqualStrings("v=aG9saSA6KSEh", verifier_result);
}
