const std = @import("std");
const rlp = @import("zig-rlp");
const types = @import("types.zig");
const Allocator = std.mem.Allocator;
const Arena = std.heap.ArenaAllocator;
const Withdrawal = types.Withdrawal;
const Txn = types.Txn;
const Hash32 = types.Hash32;
const Bytes32 = types.Bytes32;
const Address = types.Address;

pub const empty_uncle_hash: types.Hash32 = [_]u8{ 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182, 204, 212, 26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71 };
pub const LogsBloom = [256]u8;

pub const BlockHeader = struct {
    parent_hash: Hash32,
    uncle_hash: Hash32,
    fee_recipient: Address,
    state_root: Bytes32,
    transactions_root: Bytes32,
    receipts_root: Bytes32,
    logs_bloom: LogsBloom,
    difficulty: u64,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    prev_randao: Bytes32,
    nonce: [8]u8,
    base_fee_per_gas: u256,
    withdrawals_root: Hash32,

    pub fn clone(self: BlockHeader, allocator: Allocator) !BlockHeader {
        var ret = self;
        ret.extra_data = try allocator.dupe(u8, self.extra_data);
        return ret;
    }

    pub fn deinit(self: *BlockHeader, allocator: Allocator) void {
        allocator.free(self.extra_data);
        self.* = undefined;
    }
};

pub const Block = struct {
    header: BlockHeader,
    transactions: []Txn,
    uncles: []BlockHeader,
    withdrawals: []Withdrawal,

    pub fn decode(arena: Allocator, rlp_bytes: []const u8) !Block {
        var block: Block = undefined;
        _ = try rlp.deserialize(Block, arena, rlp_bytes, &block);
        return block;
    }
};

// NOTE: this test uses a bock from an old, pre-shanghai testnet.
// I have deactivated it and will replace it with a kaustinen
// block when I publish my progress with zig-verkle.
// var test_allocator = std.testing.allocator;

// test "decode vkt block sample" {
//     const block = try Block.init(@embedFile("testdata/block2.rlp"));
//     try std.testing.expectEqualStrings(
//         "904e3f9205902a780563d861aaa9cd1d635597ad1893a92d7f83dc5fb51b6eb4",
//         &bytesToHex(block.header.parent_hash),
//     );
//     try std.testing.expectEqualStrings(
//         "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
//         &bytesToHex(block.header.uncle_hash),
//     );
//     try std.testing.expectEqualStrings(
//         "0000000000000000000000000000000000000000",
//         &bytesToHex(block.header.fee_recipient),
//     );
//     try std.testing.expectEqualStrings(
//         "350f40f771a73cd6bda4c37283b88c771179469b07633568b6047cf649b8c7d1",
//         &bytesToHex(block.header.state_root),
//     );
//     try std.testing.expectEqualStrings(
//         "5f25ec3493913aef80e3d1d99e653321be3db3b16c3c83b82e6081cdce66a55c",
//         &bytesToHex(block.header.transactions_root),
//     );
//     try std.testing.expectEqualStrings(
//         "8d7a148023d3a4612e85b2f142dcec65c358ab7fbd3aebdfef6868c018d44e3c",
//         &bytesToHex(block.header.receipts_root),
//     );
//     try std.testing.expectEqualStrings(
//         "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//         &bytesToHex(block.header.logs_bloom),
//     );
//     try std.testing.expectEqualStrings(
//         "0200000000000000000000000000000000000000000000000000000000000000",
//         &bytesToHex(block.header.prev_randao),
//     );
//     try std.testing.expectEqual(@as(i64, 2), block.header.block_number);
//     try std.testing.expectEqual(@as(i64, 0x47e7c4), block.header.gas_limit);
//     try std.testing.expectEqual(@as(u64, 0x05802b), block.header.gas_used);
//     try std.testing.expectEqual(@as(i64, 0x14), block.header.timestamp);
//     try std.testing.expect(block.header.extra_data.len == 0);
//     try std.testing.expectEqual(@as(u256, 0), block.header.mix_hash);
//     try std.testing.expectEqual(@as(u256, 0x2de81128), block.header.base_fee_per_gas.?);
// }

// fn bytesToHex(bytes: anytype) [bytes.len * 2]u8 {
//     return std.fmt.bytesToHex(bytes, std.fmt.Case.lower);
// }
