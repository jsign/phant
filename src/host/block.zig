const std = @import("std");
const rlp = @import("zig-rlp");
const types = @import("types.zig");

var test_allocator = std.testing.allocator;

test "decode" {
    var block_bytes = @embedFile("block2.rlp");

    var block: types.VerkleBlock = std.mem.zeroes(types.VerkleBlock);
    const z = try rlp.deserialize(types.VerkleBlock, block_bytes, &block);
    _ = z;

    std.debug.print("gas_used: {x}\n", .{block.header.gas_used});
}
