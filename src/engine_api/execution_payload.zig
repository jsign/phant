const std = @import("std");
const types = @import("../types/types.zig");
const lib = @import("../lib.zig");
const blockchain = lib.blockchain;
const state = lib.state;
const Allocator = std.mem.Allocator;
const BlockHeader = types.BlockHeader;
const Withdrawal = types.Withdrawal;
const Tx = types.Tx;

pub const ExecutionPayload = struct {
    parentHash: types.Hash32,
    feeRecipient: types.Address,
    stateRoot: types.Hash32,
    receiptsRoot: types.Hash32,
    logsBloom: [256]u8,
    prevRandao: types.Hash32,
    blockNumber: u64,
    gasLimit: u64,
    gasUsed: u64,
    timestamp: u64,
    extraData: []const u8,
    baseFeePerGas: u256,
    blockHash: types.Hash32,
    transactions: []Tx,

    withdrawals: []types.Withdrawal,
    blobGasUsed: ?u64,
    excessBlobGas: ?u64,
    // executionWitness : ?types.ExecutionWitness,

    allocator: Allocator,

    pub fn toBlock(self: *const ExecutionPayload) types.Block {
        return types.Block{
            .header = types.BlockHeader{
                .parent_hash = self.parentHash,
                .uncle_hash = types.empty_uncle_hash,
                .fee_recipient = self.feeRecipient,
                .state_root = self.stateRoot,
                .receipts_root = self.receiptsRoot,
                .logs_bloom = self.logsBloom,
                .difficulty = 0,
                .prev_randao = self.prevRandao,
                .block_number = @intCast(self.blockNumber),
                .gas_limit = @intCast(self.gasLimit),
                .gas_used = self.gasUsed,
                .timestamp = @intCast(self.timestamp),
                .extra_data = self.extraData,
                .base_fee_per_gas = self.baseFeePerGas,
                .transactions_root = [_]u8{0} ** 32,
                .nonce = [_]u8{0} ** 8,
                .withdrawals_root = [_]u8{0} ** 32,
            },
            .transactions = self.transactions,
            .withdrawals = self.withdrawals,
            .uncles = &[0]BlockHeader{},
        };
    }

    pub fn deinit(self: *ExecutionPayload, allocator: std.mem.Allocator) void {
        if (self.extraData.len > 0) {
            allocator.free(self.extraData);
        }
    }
};

pub fn newPayloadV2Handler(params: *ExecutionPayload) !void {
    const block = params.toBlock();
    _ = block;
    // TODO reconstruct the proof from the (currently undefined) execution witness
    // and verify it. Then execute the block and return the result.
    // bc.run_block(block, params.transactions);

    // But so far, just print the content of the payload
    // std.log.info("newPayloadV2Handler: {any}", .{params});

    // std.debug.print("block number={}\n", .{block.header.block_number});
}
