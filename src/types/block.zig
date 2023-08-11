const std = @import("std");
const rlp = @import("zig-rlp");
const types = @import("types.zig");
const Transaction = types.Transaction;

const BYTES_PER_LOGS_BLOOM = 256;

pub const Block = struct {
    header: Header,
    // TODO(jsign): missing fields (i.e: txns).

    // new returns a new Block deserialized from rlp_bytes.
    // The returned Block has references to the rlp_bytes slice.
    pub fn init(rlp_bytes: []const u8) !Block {
        var block = std.mem.zeroes(Block);
        _ = try rlp.deserialize(Block, rlp_bytes, &block);
        // TODO: consider strict checking of returned deserialized length vs rlp_bytes.len.
        return block;
    }
};

pub const Header = struct {
    parent_hash: types.Hash32,
    uncle_hash: types.Hash32,
    fee_recipient: types.Address,
    state_root: types.Bytes32,
    transactions_root: types.Bytes32,
    receipts_root: types.Bytes32,
    logs_bloom: [BYTES_PER_LOGS_BLOOM]u8,
    prev_randao: types.Bytes32,
    block_number: i64,
    gas_limit: i64,
    gas_used: u64,
    timestamp: i64,
    extra_data: []const u8,
    mix_hash: u256,
    nonce: [8]u8,
    base_fee_per_gas: u256,
};

var test_allocator = std.testing.allocator;
test "decode vkt block sample" {
    const block = try Block.init(@embedFile("testdata/block2.rlp"));
    try std.testing.expectEqualStrings(
        "904e3f9205902a780563d861aaa9cd1d635597ad1893a92d7f83dc5fb51b6eb4",
        &bytesToHex(block.header.parent_hash),
    );
    try std.testing.expectEqualStrings(
        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        &bytesToHex(block.header.uncle_hash),
    );
    try std.testing.expectEqualStrings(
        "0000000000000000000000000000000000000000",
        &bytesToHex(block.header.fee_recipient),
    );
    try std.testing.expectEqualStrings(
        "350f40f771a73cd6bda4c37283b88c771179469b07633568b6047cf649b8c7d1",
        &bytesToHex(block.header.state_root),
    );
    try std.testing.expectEqualStrings(
        "5f25ec3493913aef80e3d1d99e653321be3db3b16c3c83b82e6081cdce66a55c",
        &bytesToHex(block.header.transactions_root),
    );
    try std.testing.expectEqualStrings(
        "8d7a148023d3a4612e85b2f142dcec65c358ab7fbd3aebdfef6868c018d44e3c",
        &bytesToHex(block.header.receipts_root),
    );
    try std.testing.expectEqualStrings(
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        &bytesToHex(block.header.logs_bloom),
    );
    try std.testing.expectEqualStrings(
        "0200000000000000000000000000000000000000000000000000000000000000",
        &bytesToHex(block.header.prev_randao),
    );
    try std.testing.expectEqual(@as(i64, 2), block.header.block_number);
    try std.testing.expectEqual(@as(i64, 0x47e7c4), block.header.gas_limit);
    try std.testing.expectEqual(@as(u64, 0x05802b), block.header.gas_used);
    try std.testing.expectEqual(@as(i64, 0x14), block.header.timestamp);
    try std.testing.expect(block.header.extra_data.len == 0);
    try std.testing.expectEqual(@as(u256, 0), block.header.mix_hash);
    try std.testing.expectEqual(@as(u256, 0x2de81128), block.header.base_fee_per_gas);
}

fn bytesToHex(bytes: anytype) [bytes.len * 2]u8 {
    return std.fmt.bytesToHex(bytes, std.fmt.Case.lower);
}
