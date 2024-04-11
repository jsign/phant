const std = @import("std");
const types = @import("../types/types.zig");
const common = @import("../common/common.zig");
const blocks = @import("../types/block.zig");
const config = @import("../config/config.zig");
const transaction = @import("../types/transaction.zig");
const vm = @import("vm.zig");
const rlp = @import("zig-rlp");
const signer = @import("../signer/signer.zig");
const params = @import("params.zig");
const blockchain_types = @import("types.zig");
const mpt = @import("../mpt/mpt.zig");
const Allocator = std.mem.Allocator;
const AddressSet = common.AddressSet;
const AddresssKey = common.AddressKey;
const AddressKeySet = common.AddressKeySet;
const LogsBloom = types.LogsBloom;
const Block = types.Block;
const Tx = types.Tx;
const BlockHeader = types.BlockHeader;
const Environment = blockchain_types.Environment;
const Message = blockchain_types.Message;
const StateDB = @import("../state/state.zig").StateDB;
const Hash32 = types.Hash32;
const Bytes32 = types.Bytes32;
const Address = types.Address;
const Receipt = types.Receipt;
const Log = types.Log;
const TxSigner = signer.TxSigner;
const VM = vm.VM;
const Keccak256 = std.crypto.hash.sha3.Keccak256;

pub const Blockchain = struct {
    allocator: Allocator,
    chain_id: config.ChainId,
    state: *StateDB,
    prev_block: BlockHeader,
    last_256_blocks_hashes: [256]Hash32, // ordered in asc order
    tx_signer: TxSigner,

    // init initializes a blockchain.
    // The caller **does not** transfer ownership of prev_block.
    pub fn init(
        allocator: Allocator,
        chain_id: config.ChainId,
        state: *StateDB,
        prev_block: BlockHeader,
        last_256_blocks_hashes: [256]Hash32,
    ) !Blockchain {
        return .{
            .allocator = allocator,
            .chain_id = chain_id,
            .state = state,
            .prev_block = try prev_block.clone(allocator),
            .last_256_blocks_hashes = last_256_blocks_hashes,
            .tx_signer = try signer.TxSigner.init(@intFromEnum(chain_id)),
        };
    }

    pub fn runBlock(self: *Blockchain, block: Block) !void {
        try validateBlockHeader(self.allocator, self.prev_block, block.header);
        if (block.uncles.len != 0)
            return error.NotEmptyUncles;

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        // Execute block.
        var result = try applyBody(allocator, self, self.state, block, self.tx_signer);

        // Post execution checks.
        if (result.gas_used != block.header.gas_used)
            return error.InvalidGasUsed;
        if (!std.mem.eql(u8, &result.transactions_root, &block.header.transactions_root))
            return error.InvalidTransactionsRoot;
        if (!std.mem.eql(u8, &result.receipts_root, &block.header.receipts_root))
            return error.InvalidReceiptsRoot;
        // TODO: disabled until state root is calculated
        // if (!std.mem.eql(u8, &self.state.root(), &block.header.state_root))
        //     return error.InvalidStateRoot;
        // TODO: disabled until logs bloom are calculated
        // if (!std.mem.eql(u8, &result.logs_bloom, &block.header.logs_bloom))
        //     return error.InvalidLogsBloom;
        if (!std.mem.eql(u8, &result.withdrawals_root, &block.header.withdrawals_root))
            return error.InvalidWithdrawalsRoot;

        // Add the current block to the last 256 block hashes.
        // TODO: this can be done more efficiently with some ring buffer to avoid copying the slice
        // to make room for the new block hash.
        std.mem.copyForwards(Hash32, &self.last_256_blocks_hashes, self.last_256_blocks_hashes[1..255]);
        self.last_256_blocks_hashes[255] = try common.decodeRLPAndHash(BlockHeader, allocator, block.header, null);

        // Note that we free and clone with the Blockchain allocator, and not the arena allocator.
        // This is required since Blockchain field lifetimes are longer than the block execution processing.
        self.prev_block.deinit(self.allocator);
        self.prev_block = try block.header.clone(self.allocator);
    }

    // validateBlockHeader validates the header of a block itself and with respect with the parent.
    // If isn't valid, it returns an error.
    fn validateBlockHeader(allocator: Allocator, prev_block: BlockHeader, curr_block: BlockHeader) !void {
        try checkGasLimit(curr_block.gas_limit, prev_block.gas_limit);
        if (curr_block.gas_used > curr_block.gas_limit)
            return error.GasLimitExceeded;

        // Check base fee.
        const parent_gas_target = prev_block.gas_limit / params.elasticity_multiplier;
        var expected_base_fee_per_gas = if (prev_block.gas_used == parent_gas_target)
            prev_block.base_fee_per_gas
        else if (prev_block.gas_used > parent_gas_target) blk: {
            const gas_used_delta = prev_block.gas_used - parent_gas_target;
            const base_fee_per_gas_delta = @max(prev_block.base_fee_per_gas * gas_used_delta / parent_gas_target / params.base_fee_max_change_denominator, 1);
            break :blk prev_block.base_fee_per_gas + base_fee_per_gas_delta;
        } else blk: {
            const gas_used_delta = parent_gas_target - prev_block.gas_used;
            const base_fee_per_gas_delta = prev_block.base_fee_per_gas * gas_used_delta / parent_gas_target / params.base_fee_max_change_denominator;
            break :blk prev_block.base_fee_per_gas - base_fee_per_gas_delta;
        };
        if (expected_base_fee_per_gas != curr_block.base_fee_per_gas)
            return error.InvalidBaseFee;

        if (curr_block.timestamp <= prev_block.timestamp)
            return error.InvalidTimestamp;
        if (curr_block.block_number != prev_block.block_number + 1)
            return error.InvalidBlockNumber;
        if (curr_block.extra_data.len > 32)
            return error.ExtraDataTooLong;

        if (curr_block.difficulty != 0)
            return error.InvalidDifficulty;
        if (!std.mem.eql(u8, &curr_block.nonce, &[_]u8{0} ** 8))
            return error.InvalidNonce;
        if (!std.mem.eql(u8, &curr_block.uncle_hash, &blocks.empty_uncle_hash))
            return error.InvalidUnclesHash;

        const prev_block_hash = try common.decodeRLPAndHash(BlockHeader, allocator, prev_block, null);
        if (!std.mem.eql(u8, &curr_block.parent_hash, &prev_block_hash))
            return error.InvalidParentHash;
    }

    fn checkGasLimit(gas_limit: u256, parent_gas_limit: u256) !void {
        const max_delta = parent_gas_limit / params.gas_limit_adjustement_factor;
        if (gas_limit >= parent_gas_limit + max_delta) return error.GasLimitTooHigh;
        if (gas_limit <= parent_gas_limit - max_delta) return error.GasLimitTooLow;
        if (gas_limit < params.gas_limit_minimum) return error.GasLimitLessThanMinimum;
    }

    const BlockExecutionResult = struct {
        gas_used: u64,
        transactions_root: Hash32,
        receipts_root: Hash32,
        logs_bloom: LogsBloom,
        withdrawals_root: Hash32,
    };

    fn applyBody(allocator: Allocator, chain: *Blockchain, state: *StateDB, block: Block, tx_signer: TxSigner) !BlockExecutionResult {
        var gas_available = block.header.gas_limit;

        var receipts = try allocator.alloc(Receipt, block.transactions.len);
        defer allocator.free(receipts);

        for (block.transactions, 0..) |tx, i| {
            const tx_info = try checkTransaction(allocator, tx, block.header.base_fee_per_gas, gas_available, tx_signer);

            const env: Environment = .{
                .origin = tx_info.sender_address,
                .block_hashes = chain.last_256_blocks_hashes,
                .coinbase = block.header.fee_recipient,
                .number = block.header.block_number,
                .gas_limit = block.header.gas_limit,
                .base_fee_per_gas = block.header.base_fee_per_gas,
                .gas_price = tx_info.effective_gas_price,
                .time = block.header.timestamp,
                .prev_randao = block.header.prev_randao,
                .state = state,
                .chain_id = chain.chain_id,
            };

            try state.startTx();
            const exec_tx_result = try processTransaction(allocator, env, tx);
            gas_available -= exec_tx_result.gas_used;

            // Create receipt.
            const cumm_gas_used = block.header.gas_limit - gas_available;
            receipts[i] = Receipt.init(exec_tx_result.success, cumm_gas_used, &[_]Log{});

            // TODO: do tx logs aggregation.
        }

        const block_gas_used = block.header.gas_limit - gas_available;

        // TODO: logs bloom calculation.

        for (block.withdrawals) |w| {
            const newBalance = (state.getAccount(w.address).balance + w.amount) * std.math.pow(u256, 10, 9);
            try state.setBalance(w.address, newBalance);
        }

        return .{
            .gas_used = block_gas_used,
            .transactions_root = try calculateMPTRoot(allocator, block.transactions),
            .receipts_root = try calculateMPTRoot(allocator, receipts),
            .logs_bloom = block.header.logs_bloom,
            .withdrawals_root = try calculateMPTRoot(allocator, block.withdrawals),
        };
    }

    // calculateMPTRoot generates a MPT tree of the items where keys are their index in the `items` slice.
    // The `items` slice type must implement an `encode(Allocator)` function that returns the RLP encoding.
    fn calculateMPTRoot(arena: Allocator, items: anytype) !Hash32 {
        var keyvals = try arena.alloc(mpt.KeyVal, items.len);
        defer arena.free(keyvals);

        var i: usize = 0;
        while (i + 1 < items.len and i + 1 != 0x80) : (i += 1) {
            const encoded_item = try items[i + 1].encode(arena);
            keyvals[i] = try mpt.KeyVal.init(arena, &[_]u8{@as(u8, @intCast(i + 1))}, encoded_item);
        }

        if (items.len > 0) {
            var encoded_item = try items[0].encode(arena);
            keyvals[i] = try mpt.KeyVal.init(arena, &[_]u8{0x80}, encoded_item);
            i += 1;
        }

        while (i < items.len) : (i += 1) {
            var out = std.ArrayList(u8).init(arena);
            defer out.deinit();
            try rlp.serialize(usize, arena, i, &out);

            const encoded_item = try items[i].encode(arena);
            keyvals[i] = try mpt.KeyVal.init(arena, out.items, encoded_item);
        }

        return try mpt.mptize(arena, keyvals);
    }

    fn checkTransaction(allocator: Allocator, tx: transaction.Tx, base_fee_per_gas: u256, gas_available: u64, tx_signer: TxSigner) !struct { sender_address: Address, effective_gas_price: u256 } {
        if (tx.getGasLimit() > gas_available)
            return error.InsufficientGas;

        const sender_address = try tx_signer.get_sender(allocator, tx);

        const effective_gas_price = switch (tx) {
            .FeeMarketTx => |fm_tx| blk: {
                if (fm_tx.max_fee_per_gas < fm_tx.max_priority_fee_per_gas)
                    return error.InvalidMaxFeePerGas;
                if (fm_tx.max_fee_per_gas < base_fee_per_gas)
                    return error.MaxFeePerGasLowerThanBaseFee;

                const priority_fee_per_gas = @min(fm_tx.max_priority_fee_per_gas, fm_tx.max_fee_per_gas - base_fee_per_gas);
                break :blk priority_fee_per_gas + base_fee_per_gas;
            },
            .LegacyTx, .AccessListTx => blk: {
                if (tx.getGasPrice() < base_fee_per_gas)
                    return error.GasPriceLowerThanBaseFee;
                break :blk tx.getGasPrice();
            },
        };
        return .{ .sender_address = sender_address, .effective_gas_price = effective_gas_price };
    }

    fn processTransaction(allocator: Allocator, env: Environment, tx: transaction.Tx) !struct { success: bool, gas_used: u64 } {
        if (!validateTransaction(tx))
            return error.InvalidTransaction;

        const sender = env.origin;

        const gas_fee = tx.getGasLimit() * tx.getGasPrice();

        var sender_account = env.state.getAccount(sender);
        if (sender_account.nonce != tx.getNonce())
            return error.InvalidTxNonce;
        if (sender_account.balance < gas_fee + tx.getValue())
            return error.NotEnoughBalance;
        if (sender_account.code.len > 0)
            return error.SenderIsNotEOA;

        const gas = tx.getGasLimit() - calculateIntrinsicCost(tx);
        const effective_gas_fee = tx.getGasLimit() * env.gas_price;
        try env.state.incrementNonce(sender);

        const sender_balance_after_gas_fee = sender_account.balance - effective_gas_fee;
        try env.state.setBalance(sender, sender_balance_after_gas_fee);

        try env.state.putAccessedAccount(env.coinbase);
        switch (tx) {
            .LegacyTx => {},
            inline else => |al_tx| {
                for (al_tx.access_list) |al| {
                    try env.state.putAccessedAccount(al.address);
                    for (al.storage_keys) |key| {
                        try env.state.putAccessedStorageKeys(.{ .address = al.address, .key = key });
                    }
                }
            },
        }

        var message = try prepareMessage(
            allocator,
            sender,
            tx.getTo(),
            tx.getValue(),
            tx.getData(),
            gas,
            env,
        );
        const output = try processMessageCall(message, env);

        const gas_used = tx.getGasLimit() - output.gas_left;
        const gas_refund = @min(gas_used / 5, output.refund_counter);
        const gas_refund_amount = (output.gas_left + gas_refund) * env.gas_price;

        const priority_fee_per_gas = env.gas_price - env.base_fee_per_gas;
        const transaction_fee = (tx.getGasLimit() - output.gas_left) * priority_fee_per_gas;
        const total_gas_used = gas_used - gas_refund;

        sender_account = env.state.getAccount(sender);
        const sender_balance_after_refund = sender_account.balance + gas_refund_amount;
        try env.state.setBalance(sender, sender_balance_after_refund);

        const coinbase_account = env.state.getAccount(env.coinbase);
        const coinbase_balance_after_mining_fee = coinbase_account.balance + transaction_fee;

        if (coinbase_balance_after_mining_fee != 0) {
            try env.state.setBalance(env.coinbase, coinbase_balance_after_mining_fee);
        } else if (env.state.accountExistsAndIsEmpty(env.coinbase)) {
            env.state.destroyAccount(env.coinbase);
        }

        // TODO: self destruct processing
        // for address in output.accounts_to_delete:
        //  destroy_account(env.state, address)

        for (env.state.touched_addresses.items) |address| {
            if (env.state.isEmpty(address))
                env.state.destroyAccount(address);
        }

        return .{ .success = output.success, .gas_used = total_gas_used };
    }

    fn validateTransaction(tx: transaction.Tx) bool {
        if (calculateIntrinsicCost(tx) > tx.getGasLimit())
            return false;
        if (tx.getNonce() >= (2 << 64) - 1)
            return false;
        if (tx.getTo() == null and tx.getData().len > 2 * params.max_code_size)
            return false;
        return true;
    }

    fn calculateIntrinsicCost(tx: transaction.Tx) u64 {
        var data_cost: u64 = 0;
        const data = tx.getData();
        for (data) |byte| {
            data_cost += if (byte == 0) params.tx_data_cost_per_zero else params.tx_data_cost_per_non_zero;
        }

        const create_cost = if (tx.getTo() == null) params.tx_create_cost + initCodeCost(data.len) else 0;

        const access_list_cost = switch (tx) {
            .LegacyTx => 0,
            inline else => |al_tx| blk: {
                var sum: u64 = 0;
                for (al_tx.access_list) |al| {
                    data_cost += params.tx_access_list_address_cost;
                    data_cost += al.storage_keys.len * params.tx_access_list_storage_key_cost;
                }
                break :blk sum;
            },
        };

        return params.tx_base_cost + data_cost + create_cost + access_list_cost;
    }

    fn initCodeCost(code_length: usize) u64 {
        return params.gas_init_code_word_const * (code_length + 31) / 32;
    }

    // prepareMessage prepares an EVM message.
    // The caller must call deinit() on the returned Message.
    pub fn prepareMessage(
        allocator: Allocator,
        caller: Address,
        target: ?Address,
        value: u256,
        data: []const u8,
        gas: u64,
        env: Environment,
    ) !Message {
        var current_target: Address = undefined;
        var code_address: Address = undefined;
        var msg_data: []const u8 = undefined;
        var code: []const u8 = undefined;

        if (target) |targ| {
            current_target = targ;
            msg_data = data;
            code = env.state.getAccount(targ).code;
            code_address = targ;
        } else {
            current_target = try computeContractAddress(allocator, caller, env.state.getAccount(caller).nonce - 1);
            msg_data = &[_]u8{0};
            code = data;
        }

        try env.state.putAccessedAccount(current_target);
        try env.state.putAccessedAccount(caller);
        for (params.precompiled_contract_addresses) |precompile_addr| {
            try env.state.putAccessedAccount(precompile_addr);
        }

        return .{
            .caller = caller,
            .target = target,
            .current_target = current_target,
            .gas = gas,
            .value = value,
            .data = msg_data,
            .code_address = code_address,
            .code = code,
        };
    }

    fn computeContractAddress(allocator: Allocator, address: Address, nonce: u64) !Address {
        var out = std.ArrayList(u8).init(allocator);
        defer out.deinit();
        try rlp.serialize(struct { addr: Address, nonce: u64 }, allocator, .{ .addr = address, .nonce = nonce }, &out);

        var computed_address: [Keccak256.digest_length]u8 = undefined;
        Keccak256.hash(out.items, &computed_address, .{});

        var padded_address: Address = std.mem.zeroes(Address);
        @memcpy(&padded_address, computed_address[12..]);

        return padded_address;
    }

    fn processMessageCall(message: Message, env: Environment) !vm.MessageCallOutput {
        var vm_instance = VM.init(env);
        defer vm_instance.deinit();

        return try vm_instance.processMessageCall(message);
    }
};
