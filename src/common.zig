const std = @import("std");

pub fn deserializePart(identifier: []const u8, msg: []const u8) ![]const u8 {
    if (try deserializeOptionalPart(identifier, msg)) |part| {
        return part;
    } else return error.Invalid;
}

pub fn deserializeOptionalPart(identifier: []const u8, msg: ?[]const u8) !?[]const u8 {
    if (msg == null) return null;

    var parts = std.mem.splitScalar(u8, msg.?, '=');
    if (!std.mem.eql(u8, parts.first(), identifier)) return null;

    // TODO: Special deserialization for ','?

    if (parts.peek() == null) return error.Invalid;
    return parts.rest();
}

const base64 = std.base64.standard.Encoder;
pub fn defaultNonceGenerator(alloc: std.mem.Allocator) ![]const u8 {
    var raw = try alloc.alloc(u8, 24);
    defer alloc.free(raw);

    std.crypto.random.bytes(raw);

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
