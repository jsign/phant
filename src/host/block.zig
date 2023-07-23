const std = @import("std");
const rlp = @import("zig-rlp");

var test_allocator = std.testing.allocator;

const Hash32 = [32]u8;
const ExecutionAddress = [20]u8;
const Bytes32 = [32]u8;
const BYTES_PER_LOGS_BLOOM = 256;

const VerkleBlock = struct {
    header: VerkleHeader,
};

const VerkleHeader = struct {
    parent_hash: Hash32,
    xxx: Hash32, // ???
    fee_recipient: ExecutionAddress,
    state_root: Bytes32,
    receipts_root: Bytes32,
    xxy: Bytes32, // ???
    logs_bloom: [BYTES_PER_LOGS_BLOOM]u8,
    prev_randao: Bytes32,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    base_fee_per_gas: u256,
    xxz: [8]u8, // ???
    xxzz: [4]u8, // ???
};

test "decode" {
    var block_bytes = @embedFile("block2.rlp");

    var block: VerkleBlock = undefined;
    const z = try rlp.deserialize(VerkleBlock, block_bytes, &block);
    _ = z;

    std.debug.print("gas_used: {x}\n", .{block.header.gas_used});
}
