const std = @import("std");
const gs2 = @import("gs2.zig");
const common = @import("common.zig");
const server = @import("server.zig");

pub const ClientSha1 = Client(std.crypto.hash.Sha1);
pub const ClientSha256 = Client(std.crypto.hash.sha2.Sha256);
pub const ClientSha512 = Client(std.crypto.hash.sha3.Sha3_512);

pub fn Client(comptime Hash: type) type {
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);

    return struct {
        const Self = @This();

        alloc: std.mem.Allocator,
        username: []const u8,
        password: []const u8,
        nonce: []const u8,
        nonce_generated: bool,

        client_first_bare: ?[]const u8 = null,
        server_signature: [Hmac.mac_length]u8 = undefined,

        pub fn init(alloc: std.mem.Allocator, username: []const u8, password: []const u8, nonce: ?[]const u8) !Self {
            return .{
                .alloc = alloc,
                .username = username,
                .password = password,
                .nonce = nonce orelse try common.defaultNonceGenerator(alloc),
                .nonce_generated = nonce != null,
            };
        }

        pub fn deinit(self: *Self) void {
            if (!self.nonce_generated) self.alloc.free(self.nonce);
            if (self.client_first_bare) |f| self.alloc.free(f);
        }

        pub fn clientFirst(self: *Self) ![]const u8 {
            const c = ClientFirst{
                .header = gs2.Header{ .cbind_flag = .{ .N = {} } },
                .username = self.username,
                .nonce = self.nonce,
            };

            self.client_first_bare = try c.serializeBare(self.alloc);

            return try c.serialize(self.alloc, self.client_first_bare.?);
        }

        pub fn clientFinal(self: *Self, msg: []const u8) ![]const u8 {
            var server_first = try server.ServerFirst.deserialize(self.alloc, msg);
            defer server_first.deinit(self.alloc);

            var c = ClientFinal{
                .header = gs2.Header{ .cbind_flag = .{ .N = {} } },
                .nonce = server_first.nonce,
                .proof = undefined,
            };
            var without_proof = try c.serializeWithoutProof(self.alloc);
            defer self.alloc.free(without_proof);

            var salted_password = try self.alloc.alloc(u8, Hash.digest_length);
            defer self.alloc.free(salted_password);

            try std.crypto.pwhash.pbkdf2(salted_password, self.password, server_first.salt, server_first.iteration_count, Hmac);

            var client_key: [Hmac.mac_length]u8 = undefined;
            Hmac.create(&client_key, "Client Key", salted_password);

            var stored_key: [Hash.digest_length]u8 = undefined;
            Hash.hash(&client_key, &stored_key, .{});

            var auth_message = try std.mem.concat(self.alloc, u8, &.{
                self.client_first_bare.?,
                ",",
                msg,
                ",",
                without_proof,
            });
            defer self.alloc.free(auth_message);

            var client_signature: [Hmac.mac_length]u8 = undefined;
            Hmac.create(&client_signature, auth_message, &stored_key);

            var client_proof = client_key;
            for (client_signature, 0..) |value, i| {
                client_proof[i] ^= value;
            }

            c.proof = &client_proof;

            var server_key: [Hmac.mac_length]u8 = undefined;
            Hmac.create(&server_key, "Server Key", salted_password);

            Hmac.create(&self.server_signature, auth_message, &server_key);

            return try c.serialize(self.alloc, without_proof);
        }

        pub fn verify(self: *Self, msg: []const u8) !void {
            var server_final = try server.ServerFinal.deserialize(self.alloc, msg);
            defer server_final.deinit(self.alloc);

            switch (server_final) {
                .err => @panic("error!"),
                .signature => |s| {
                    if (!std.mem.eql(u8, s, &self.server_signature)) {
                        @panic("invalid signature!");
                    }
                },
            }
        }
    };
}

test "Client should send the client first message correctly" {
    var allocator = std.testing.allocator;

    var c = try ClientSha256.init(allocator, "nefix", "s3cr3t", "hello :)");
    defer c.deinit();

    const client_first = try c.clientFirst();
    defer allocator.free(client_first);

    try std.testing.expectEqualStrings("n,,n=nefix,r=hello :)", client_first);
}

test "Client should send the client final message correctly" {
    var allocator = std.testing.allocator;
    {
        // Taken from https://datatracker.ietf.org/doc/html/rfc5802
        var c = try ClientSha1.init(allocator, "user", "pencil", "fyko+d2lbbFgONRv9qkxdawL");
        defer c.deinit();

        const first = try c.clientFirst();
        defer allocator.free(first);

        const result = try c.clientFinal("r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096");
        defer allocator.free(result);

        try std.testing.expectEqualStrings("c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=", result);
    }

    {
        // Taken from https://github.com/star-tek-mb/pgz/blob/master/src/auth.zig
        var c = try ClientSha256.init(allocator, "", "foobar", "9IZ2O01zb9IgiIZ1WJ/zgpJB");
        defer c.deinit();

        const first = try c.clientFirst();
        defer allocator.free(first);

        const result = try c.clientFinal("r=9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY,s=fs3IXBy7U7+IvVjZ,i=4096");
        defer allocator.free(result);

        try std.testing.expectEqualStrings("c=biws,r=9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY,p=AmNKosjJzS31NTlQYNs5BTeQjdHdk7lOflDo5re2an8=", result);
    }
}

pub const ClientFirst = struct {
    header: gs2.Header,
    reserved_mext: ?[]const u8 = null,
    username: []const u8,
    nonce: []const u8,
    extensions: ?[][]const u8 = null,

    pub fn serialize(self: ClientFirst, alloc: std.mem.Allocator, bare: []const u8) ![]const u8 {
        const header = try self.header.serialize(alloc);
        defer alloc.free(header);

        return try std.mem.concat(alloc, u8, &.{
            header,
            bare,
        });
    }

    pub fn serializeBare(self: ClientFirst, alloc: std.mem.Allocator) ![]const u8 {
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
            if (self.reserved_mext) |_| "," else "",
            if (self.reserved_mext) |r| r else "",
            "n=",
            username,
            ",",
            "r=",
            self.nonce,
            extensions,
        });
    }

    pub fn deserialize(msg: []const u8) !ClientFirst {
        var parts = std.mem.splitScalar(u8, msg, ',');

        // GS2 Header
        const header = try gs2.Header.deserialize(&parts);

        // Reserved mext
        var part = parts.next();
        const reserved_mext = common.deserializeOptionalPart("m", part) catch return error.ClientFirstInvalid;

        // Username
        part = if (reserved_mext != null) parts.next() else part;
        if (part == null) return error.ClientFirstInvalid;
        const username = common.deserializePart("n", part.?) catch return error.ClientFirstInvalid;

        // Nonce
        part = parts.next();
        if (part == null) return error.ClientFirstInvalid;
        const nonce = common.deserializePart("r", part.?) catch return error.ClientFirstInvalid;

        // TODO: Extensions

        return .{
            .header = header,
            .reserved_mext = reserved_mext,
            .username = username,
            .nonce = nonce,
        };
    }
};

test "ClientFirst should serialize correctly" {
    const alloc = std.testing.allocator;

    const client = ClientFirst{
        .header = .{ .cbind_flag = .{ .N = {} } },
        .username = "nefix",
        .nonce = "nonce",
    };
    const bare = try client.serializeBare(alloc);
    defer alloc.free(bare);

    const result = try client.serialize(alloc, bare);
    defer alloc.free(result);

    try std.testing.expectEqualStrings("n,,n=nefix,r=nonce", result);
}

test "ClientFirst should deserialize correctly" {
    const client_first = "n,,n=,r=9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY";

    var c = try ClientFirst.deserialize(client_first);
    try std.testing.expectEqualDeep(ClientFirst{
        .header = .{ .cbind_flag = .{ .N = {} } },
        .username = "",
        .nonce = "9IZ2O01zb9IgiIZ1WJ/zgpJBjx/oIRLs02gGSHcw1KEty3eY",
    }, c);
}

pub const ClientFinal = struct {
    const base64Encoder = std.base64.standard.Encoder;
    const base64Decoder = std.base64.standard.Decoder;

    header: gs2.Header,
    nonce: []const u8,
    extensions: ?[][]const u8 = null,
    proof: []const u8,

    _raw_header: ?[]const u8 = null,

    pub fn serialize(self: *ClientFinal, alloc: std.mem.Allocator, without_proof: []const u8) ![]const u8 {
        var proof = try alloc.alloc(u8, base64Encoder.calcSize(self.proof.len));
        defer alloc.free(proof);
        _ = base64Encoder.encode(proof, self.proof);

        return try std.mem.concat(alloc, u8, &.{
            without_proof,
            ",",
            "p=",
            proof,
        });
    }

    pub fn deinit(self: *ClientFinal, alloc: std.mem.Allocator) void {
        if (self._raw_header) |raw| alloc.free(raw);
        alloc.free(self.proof);
    }

    pub fn serializeWithoutProof(self: ClientFinal, alloc: std.mem.Allocator) ![]const u8 {
        const header = try self.header.serialize(alloc);
        defer alloc.free(header);

        var channel_binding = try alloc.alloc(u8, base64Encoder.calcSize(header.len));
        defer alloc.free(channel_binding);
        _ = base64Encoder.encode(channel_binding, header);

        return try std.mem.concat(alloc, u8, &.{
            "c=",
            channel_binding,
            ",",
            "r=",
            self.nonce,
            // TODO: Extensions
        });
    }

    pub fn deserialize(alloc: std.mem.Allocator, msg: []const u8) !ClientFinal {
        var parts = std.mem.splitScalar(u8, msg, ',');

        // Channel binding (header)
        var part = parts.next();
        if (part == null) return error.ClientFinalInvalid;
        const channel_binding = common.deserializePart("c", part.?) catch return error.ClientFirstInvalid;

        var raw_header = try alloc.alloc(u8, try base64Decoder.calcSizeForSlice(channel_binding));
        try base64Decoder.decode(raw_header, channel_binding);

        var raw_header_split = std.mem.splitScalar(u8, raw_header, ',');
        const header = try gs2.Header.deserialize(&raw_header_split);

        part = parts.next();
        if (part == null) return error.ClientFinalInvalid;
        const nonce = common.deserializePart("r", part.?) catch return error.ClientFirstInvalid;

        // TODO: Extensions

        // Proof
        part = parts.next();
        if (part == null) return error.ClientFinalInvalid;
        const raw_proof = common.deserializePart("p", part.?) catch return error.ClientFirstInvalid;

        var proof = try alloc.alloc(u8, try base64Decoder.calcSizeForSlice(raw_proof));
        try base64Decoder.decode(proof, raw_proof);

        return ClientFinal{
            ._raw_header = raw_header,
            .header = header,
            .nonce = nonce,
            .proof = proof,
        };
    }
};

test "ClientFinal should be serialized correctly" {
    var allocator = std.testing.allocator;

    var c = ClientFinal{
        .header = gs2.Header{ .cbind_flag = gs2.CbindFlag{ .N = {} } },
        .nonce = "6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573",
        .proof = &.{ 202, 169, 187, 217, 137, 95, 178, 17, 13, 140, 244, 117, 95, 22, 167, 166, 113, 208, 63, 202 },
    };

    const without_proof = try c.serializeWithoutProof(allocator);
    defer allocator.free(without_proof);

    const result = try c.serialize(allocator, without_proof);
    defer allocator.free(result);

    try std.testing.expectEqualStrings("c=biws,r=6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573,p=yqm72YlfshENjPR1XxanpnHQP8o=", result);
}

test "ClientFinal should be deserialized correctly" {
    var alloc = std.testing.allocator;

    var c = try ClientFinal.deserialize(alloc, "c=biws,r=6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573,p=yqm72YlfshENjPR1XxanpnHQP8o=");
    defer c.deinit(alloc);

    const expected = ClientFinal{
        ._raw_header = "n,,",
        .header = gs2.Header{ .cbind_flag = gs2.CbindFlag{ .N = {} } },
        .nonce = "6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573",
        .proof = &.{ 202, 169, 187, 217, 137, 95, 178, 17, 13, 140, 244, 117, 95, 22, 167, 166, 113, 208, 63, 202 },
    };

    try std.testing.expectEqualDeep(expected, c);
}
