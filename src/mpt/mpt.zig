const std = @import("std");
const rlp = @import("zig-rlp");
const types = @import("../types/types.zig");
const Allocator = std.mem.Allocator;
const Hash32 = types.Hash32;

// indexToRLP returns the RLP representation of the index.
// The caller is responsible for freeing the returned slice.
fn indexToRLP(allocator: Allocator, index: u16) ![]const u8 {
    if (index == 0) {
        return &[_]u8{0x80};
    }
    if (index <= 127) { // Small values RLP optimized.
        var out = try allocator.alloc(u8, 1);
        out[0] = @intCast(index);
        return out;
    }
    if (index < 1 << 8) { // 1 byte.
        var out = try allocator.alloc(u8, 1 + 1);
        out[0] = 0x81;
        out[1] = @intCast(index);
        return out;
    }
    // 2 bytes.
    var out = try allocator.alloc(u8, 1 + 2);
    out[0] = 0x82;
    std.mem.writeInt(u16, out[1..3], index, std.builtin.Endian.Big);
    return out;
}

test "basic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    for (0..1000) |i| {
        for (0..i) |index| {
            const key = try indexToRLP(allocator, @intCast(index));
            const value = key;
            _ = value; // Just set the value as the key.

        }
    }
}
