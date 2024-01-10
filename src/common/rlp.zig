const std = @import("std");
const rlp = @import("zig-rlp");
const types = @import("../types/types.zig");
const hasher = @import("../crypto/crypto.zig").hasher;
const Allocator = std.mem.Allocator;
const Hash32 = types.Hash32;

pub fn decodeRLP(comptime T: type, arena: Allocator, bytes: []const u8) !T {
    var ret: T = std.mem.zeroes(T);
    _ = try rlp.deserialize(T, arena, bytes, &ret);
    return ret;
}

pub fn decodeRLPAndHash(comptime T: type, allocator: Allocator, value: T, prefix: ?[]const u8) !Hash32 {
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try rlp.serialize(T, allocator, value, &out);
    if (prefix) |pre| {
        return hasher.keccak256WithPrefix(pre, out.items);
    }
    return hasher.keccak256(out.items);
}
