const std = @import("std");
const types = @import("../types/types.zig");
const config = @import("../config/config.zig");
const vm = @import("../vm/vm.zig"); // TODO: Avoid this import?
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const StateDB = vm.StateDB;
const Hash32 = types.Hash32;

pub const Blockchain = struct {
    const BASE_FEE_MAX_CHANGE_DENOMINATOR = 8;
    const ELASTICITY_MULTIPLIER = 2;
    const GAS_LIMIT_ADJUSTMENT_FACTOR = 1024;
    const GAS_LIMIT_MINIMUM = 5000;

    chain_id: config.ChainId,
    flat_db: *StateDB,
    last_256_blocks_hashes: [256]Hash32,
    previous_block: Block,

    pub fn init(
        chain_id: config.ChainId,
        flat_db: *StateDB,
        prev_block_header: BlockHeader,
        last_256_blocks_hashes: [256]Hash32,
    ) void {
        return Blockchain{
            .chain_id = chain_id,
            .flat_db = flat_db,
            .prev_block_header = prev_block_header,
            .last_256_blocks_hashes = last_256_blocks_hashes,
        };
    }

    pub fn execute_block(self: Blockchain, block: Block) !void {
        try self.validate_block(block);
        // TODO: continue
    }

    fn validateBlockHeader(prev_block: BlockHeader, block: BlockHeader) !void {
        try checkGasLimit(block.gas_limit, prev_block.gas_limit);
        if (block.gas_used > block.gas_limit)
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
        if (expected_base_fee_per_gas != block.base_fee_per_gas)
            return error.InvalidBaseFee;
    }

    fn checkGasLimit(gas_limit: u256, parent_gas_limit: u256) !void {
        const max_delta = parent_gas_limit / GAS_LIMIT_ADJUSTMENT_FACTOR;
        if (gas_limit >= parent_gas_limit + max_delta) return error.GasLimitTooHigh;
        if (gas_limit <= parent_gas_limit - max_delta) return error.GasLimitTooLow;
        return gas_limit >= GAS_LIMIT_MINIMUM;
    }
};
