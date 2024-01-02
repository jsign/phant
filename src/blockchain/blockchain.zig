const std = @import("std");
const types = @import("../types/types.zig");
const blocks = @import("../types/block.zig");
const config = @import("../config/config.zig");
const transaction = @import("../types/transaction.zig");
const vm = @import("../vm/vm.zig"); // TODO: Avoid this import?
const rlp = @import("zig-rlp");
const Allocator = std.mem.Allocator;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const StateDB = vm.StateDB;
const Hash32 = types.Hash32;

pub const Blockchain = struct {
    const BASE_FEE_MAX_CHANGE_DENOMINATOR = 8;
    const ELASTICITY_MULTIPLIER = 2;
    const GAS_LIMIT_ADJUSTMENT_FACTOR = 1024;
    const GAS_LIMIT_MINIMUM = 5000;

    allocator: Allocator,
    chain_id: config.ChainId,
    flat_db: *StateDB,
    last_256_blocks_hashes: [256]Hash32,
    previous_block: Block,

    pub fn init(
        allocator: Allocator,
        chain_id: config.ChainId,
        flat_db: *StateDB,
        prev_block_header: BlockHeader,
        last_256_blocks_hashes: [256]Hash32,
    ) void {
        return Blockchain{
            .allocator = allocator,
            .chain_id = chain_id,
            .flat_db = flat_db,
            .prev_block_header = prev_block_header,
            .last_256_blocks_hashes = last_256_blocks_hashes,
        };
    }

    pub fn run_block(self: Blockchain, block: Block) !void {
        try self.validate_block(self.allocator, block);
        if (block.uncles.len != 0)
            return error.NotEmptyUncles;

        var result = try self.execute_block(block);

        if (result.gas_used != block.header.gas_used)
            return error.InvalidGasUsed;
        if (result.transactions_root != block.header.transactions_root) // TODO: Do before exec.
            return error.InvalidTransactionsRoot;
        if (result.receipts_root != block.header.receipts_root) // TODO: Do before exec.
            return error.InvalidReceiptsRoot;
        if (result.state.root() != block.header.state_root)
            return error.InvalidStateRoot;
        if (result.logs_bloom != block.header.logs_bloom)
            return error.InvalidLogsBloom;
        if (result.withdrawals_root != block.header.withdrawals_root)
            return error.InvalidWithdrawalsRoot;

        // TODO: do this more efficiently with a circular buffer.
        std.mem.copyForwards(Hash32, self.last_256_blocks_hashes, self.last_256_blocks_hashes[1..]);
        self.last_256_blocks_hashes[255] = block.hash();
    }

    // validateBlockHeader validates the header of a block itself and with respect with the parent.
    // If isn't valid, it returns an error.
    fn validateBlockHeader(allocator: Allocator, prev_block: BlockHeader, curr_block: BlockHeader) !void {
        try checkGasLimit(curr_block.gas_limit, prev_block.gas_limit);
        if (curr_block.gas_used > curr_block.gas_limit)
            return error.GasLimitExceeded;

        // Check base fee.
        const parent_gas_target = prev_block.gas_limit / ELASTICITY_MULTIPLIER;
        var expected_base_fee_per_gas = if (prev_block.gas_used == parent_gas_target)
            prev_block.base_fee_per_gas
        else if (prev_block.gas_used > parent_gas_target) blk: {
            const gas_used_delta = prev_block.gas_used - parent_gas_target;
            const base_fee_per_gas_delta = @max(prev_block.base_fee_per_gas * gas_used_delta / parent_gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR, 1);
            break :blk prev_block.base_fee_per_gas + base_fee_per_gas_delta;
        } else blk: {
            const gas_used_delta = parent_gas_target - prev_block.gas_used;
            const base_fee_per_gas_delta = prev_block.base_fee_per_gas * gas_used_delta / parent_gas_target / BASE_FEE_MAX_CHANGE_DENOMINATOR;
            break :blk prev_block.base_fee_per_gas - base_fee_per_gas_delta;
        };
        if (expected_base_fee_per_gas != curr_block.base_fee_per_gas)
            return error.InvalidBaseFee;

        if (curr_block.timestamp > prev_block.timestamp)
            return error.InvalidTimestamp;
        if (curr_block.block_number != prev_block.block_number + 1)
            return error.InvalidBlockNumber;
        if (curr_block.extra_data.len > 32)
            return error.ExtraDataTooLong;

        if (curr_block.difficulty != 0)
            return error.InvalidDifficulty;
        if (curr_block.nonce == [_]u8{0} ** 8)
            return error.InvalidNonce;
        if (curr_block.ommers_hash != blocks.empty_uncle_hash)
            return error.InvalidOmmersHash;

        const prev_block_hash = transaction.RLPHash(BlockHeader, allocator, prev_block, null);
        if (curr_block.parent_hash != prev_block_hash)
            return error.InvalidParentHash;
    }

    fn checkGasLimit(gas_limit: u256, parent_gas_limit: u256) !void {
        const max_delta = parent_gas_limit / GAS_LIMIT_ADJUSTMENT_FACTOR;
        if (gas_limit >= parent_gas_limit + max_delta) return error.GasLimitTooHigh;
        if (gas_limit <= parent_gas_limit - max_delta) return error.GasLimitTooLow;
        return gas_limit >= GAS_LIMIT_MINIMUM;
    }
};
