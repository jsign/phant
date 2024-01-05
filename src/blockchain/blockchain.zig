const std = @import("std");
const types = @import("../types/types.zig");
const blocks = @import("../types/block.zig");
const config = @import("../config/config.zig");
const transaction = @import("../types/transaction.zig");
const vm = @import("vm.zig");
const rlp = @import("zig-rlp");
const signer = @import("../signer/signer.zig");
const Allocator = std.mem.Allocator;
const LogsBloom = types.LogsBloom;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const StateDB = vm.StateDB;
const Hash32 = types.Hash32;
const Bytes32 = types.Bytes32;
const Address = types.Address;
const VM = vm.VM;

pub const Blockchain = struct {
    const BASE_FEE_MAX_CHANGE_DENOMINATOR = 8;
    const ELASTICITY_MULTIPLIER = 2;

    const GAS_LIMIT_ADJUSTMENT_FACTOR = 1024;
    const GAS_LIMIT_MINIMUM = 5000;
    const GAS_INIT_CODE_WORD_COST = 2;

    const MAX_CODE_SIZE = 0x6000;

    const TX_BASE_COST = 21000;
    const TX_DATA_COST_PER_ZERO = 4;
    const TX_DATA_COST_PER_NON_ZERO = 16;
    const TX_CREATE_COST = 32000;
    const TX_ACCESS_LIST_ADDRESS_COST = 2400;
    const TX_ACCESS_LIST_STORAGE_KEY_COST = 1900;

    const PRE_COMPILED_CONTRACT_ADDRESSES = [_]Address{
        // TODO: see if it's worth importing some .h file from EVMOne
        // an instantiate this at comptime to avoid maintaining this list.
        [_]u8{0} ** 19 ++ [_]u8{1}, // ECRECOVER
        [_]u8{0} ** 19 ++ [_]u8{2}, // SHA256
        [_]u8{0} ** 19 ++ [_]u8{3}, // RIPEMD160
        [_]u8{0} ** 19 ++ [_]u8{4}, // IDENTITY_ADDRESS
        [_]u8{0} ** 19 ++ [_]u8{5}, // MODEXP_ADDRESS
        [_]u8{0} ** 19 ++ [_]u8{6}, // ALT_BN128_ADD
        [_]u8{0} ** 19 ++ [_]u8{7}, // ALT_BN128_MUL
        [_]u8{0} ** 19 ++ [_]u8{8}, // ALT_BN128_PAIRING_CHECK
        [_]u8{0} ** 19 ++ [_]u8{9}, // BLAKE2F
    };

    allocator: Allocator,
    chain_id: config.ChainId,
    state: *StateDB,
    last_256_blocks_hashes: [256]Hash32,
    previous_block: Block,

    pub fn init(
        allocator: Allocator,
        chain_id: config.ChainId,
        state: *StateDB,
        prev_block_header: BlockHeader,
        last_256_blocks_hashes: [256]Hash32,
    ) void {
        return Blockchain{
            .allocator = allocator,
            .chain_id = chain_id,
            .state = state,
            .prev_block_header = prev_block_header,
            .last_256_blocks_hashes = last_256_blocks_hashes,
        };
    }

    pub fn run_block(self: Blockchain, block: Block) !void {
        try self.validate_block(self.allocator, block);
        if (block.uncles.len != 0)
            return error.NotEmptyUncles;

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();

        // Execute block.
        var result = try applyBody(arena, self, block, self.state);

        // Post execution checks.
        if (result.gas_used != block.header.gas_used)
            return error.InvalidGasUsed;
        if (result.transactions_root != block.header.transactions_root)
            return error.InvalidTransactionsRoot;
        if (result.receipts_root != block.header.receipts_root)
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

    const BlockExecutionResult = struct {
        gas_used: u64,
        transactions_root: Hash32,
        receipts_root: Hash32,
        logs_bloom: LogsBloom,
        withdrawals_root: Hash32,
    };

    fn applyBody(allocator: Allocator, chain: Blockchain, state: StateDB, block: Block) !BlockExecutionResult {
        var gas_available = block.header.gas_limit;
        for (block.transactions) |tx| {
            // TODO: add tx to txs tree.

            const txn_info = checkTransaction(allocator, tx, block.header.base_fee_per_gas, gas_available, chain.chain_id);
            const env = vm.Environment{
                .caller = txn_info.sender_address,
                .origin = txn_info.sender_address,
                .block_hashes = chain.last_256_blocks_hashes,
                .coinbase = block.header.fee_recipient,
                .number = block.header.block_number,
                .gas_limit = block.header.gas_limit,
                .base_fee_per_gas = block.header.base_fee_per_gas,
                .gas_price = txn_info.effective_gas_price,
                .time = block.header.timestamp,
                .prev_randao = block.header.prev_randao,
                .state = state,
                .chain_id = chain.chain_id,
            };

            const exec_tx_result = try processTransaction(allocator, env, tx);
            gas_available -= exec_tx_result.gas_used;

            // TODO: make receipt and add to receipt tree.
            // TODO: do tx logs aggregation.
        }

        const block_gas_used = block.header.gas_limit - gas_available;

        // TODO: logs bloom calculation.

        // TODO: process withdrawals.

        return .{
            .gas_used = block_gas_used,
            .transactions_root = std.mem.zeroes(Hash32), // TODO
            .receipts_root = std.mem.zeroes(Hash32), // TODO
            .logs_bloom = block.header.logs_bloom,
            .withdrawals_root = std.mem.zeroes(Hash32), // TODO
        };
    }

    fn checkTransaction(allocator: Allocator, tx: transaction.Txn, base_fee_per_gas: u64, gas_available: u64, chain_id: u64) !struct { sender_address: Address, effective_gas_price: config.ChainId } {
        if (tx.getGasLimit() > gas_available)
            return error.InsufficientGas;

        const txn_signer = try signer.TxnSigner.init(@intFromEnum(chain_id));
        const sender_address = txn_signer.get_sender(allocator, tx);

        const effective_gas_price = switch (tx) {
            .FeeMarketTxn => |fm_tx| blk: {
                if (fm_tx.max_fee_per_gas < fm_tx.max_priority_fee_per_gas)
                    return error.InvalidMaxFeePerGas;
                if (fm_tx.max_fee_per_gas < base_fee_per_gas)
                    return error.MaxFeePerGasLowerThanBaseFee;

                const priority_fee_per_gas = @min(tx.max_priority_fee_per_gas, tx.max_fee_per_gas - base_fee_per_gas);
                break :blk priority_fee_per_gas + base_fee_per_gas;
            },
            .LegacyTxn, .AccessListTxn => blk: {
                if (tx.getGasPrice() < base_fee_per_gas)
                    return error.GasPriceLowerThanBaseFee;
                break :blk tx.getGasPrice();
            },
        };
        return .{ .sender_address = sender_address, .effective_gas_price = effective_gas_price };
    }

    const Environment = struct {
        caller: Address,
        block_hashes: [256]Hash32,
        origin: Address,
        coinbase: Address,
        number: u64,
        base_fee_per_gas: u256,
        gas_limit: u64,
        gas_price: u64,
        time: u256,
        prev_randao: Bytes32,
        state: *StateDB,
        chain_id: config.ChainId,
    };

    const AddressSet = std.HashMap(Address, void);
    const AddressKeyTuple = struct { address: Address, key: Bytes32 };
    const AddressKeySet = std.HashMap(AddressKeyTuple, void);

    fn processTransaction(allocator: Allocator, env: Environment, tx: transaction.Txn) !struct { gas_left: u64 } {
        if (!validateTransaction(tx))
            return error.InvalidTransaction;

        const sender = env.origin;
        const sender_account = try env.state.getAccount(sender);

        const gas_fee = tx.getGasLimit() * tx.getGasPrice();

        if (sender_account.nonce != tx.nonce)
            return error.InvalidTxnNonce;
        if (sender_account.balance < gas_fee + tx.value)
            return error.NotEnoughBalance;
        if (sender_account.code != null)
            return error.SenderIsNotEOA;

        const effective_gas_fee = tx.getGasLimit() * env.gas_price;
        const gas = tx.getGasLimit() - calculateIntrinsicCost(tx);
        env.state.incrementNonce(sender);

        const sender_balance_after_gas_fee = sender_account.balance - effective_gas_fee;
        env.state.setBalance(sender, sender_balance_after_gas_fee);

        var preaccessed_addresses = AddressSet.init(allocator);
        defer preaccessed_addresses.deinit();
        var preaccessed_stoarge_keys = AddressKeySet.init(allocator);
        defer preaccessed_stoarge_keys.deinit();
        preaccessed_addresses.put(env.coinbase, null);
        switch (tx) {
            .LegacyTxn => {},
            inline else => {
                for (tx.access_list) |al| {
                    preaccessed_addresses.put(al.address, null);
                    for (al.storage_keys) |key| {
                        preaccessed_stoarge_keys.put(.{ .address = al.address, .key = key }, null);
                    }
                }
            },
        }

        const message = prepareMessage(
            sender,
            tx.getTo(),
            tx.getValue(),
            tx.getData(),
            gas,
            env,
            preaccessed_addresses,
            preaccessed_stoarge_keys,
        );
        const output = processMessageCall(message, env);

        const gas_used = tx.getGasLimit() - output.gas_left;
        const gas_refund = @min(gas_used / 5, output.refund_counter);
        const gas_refund_amount = (output.gas_left + gas_refund) * env.gas_price;

        const priority_fee_per_gas = env.gas_price - env.base_fee_per_gas;
        const transaction_fee = (tx.getGasLimit() - output.gas_left) * priority_fee_per_gas;
        const total_gas_used = gas_used - gas_refund;

        const sender_balance_after_refund = sender_account.balance + gas_refund_amount;
        env.state.setBalance(sender, sender_balance_after_refund);

        const coinbase_account = try env.state.getAccount(env.coinbase);
        const coinbase_balance_after_mining_fee = coinbase_account.balance + transaction_fee;

        if (coinbase_balance_after_mining_fee != 0) {
            env.state.setBalance(env.coinbase, coinbase_balance_after_mining_fee);
        } else if (env.state.accountExistsAndIsEmpty(env.coinbase)) {
            env.state.destroyAccount(env.coinbase);
        }

        // Account destruction is already managed by EVMC `selfdestruct(...)` callback.

        for (output.touched_accounts) |address| {
            if (env.state.accountExistsAndIsEmpty(address)) {
                env.state.destroyAccount(address);
            }
        }

        return .{ total_gas_used, output.logs, output.err };
    }

    fn validateTransaction(tx: transaction.Txn) bool {
        if (calculateIntrinsicCost(tx) > tx.getGasLimit())
            return false;
        if (tx.getNonce() >= (2 << 64) - 1)
            return false;
        if (tx.getTo() == null and tx.data.len > 2 * MAX_CODE_SIZE)
            return false;
        return true;
    }

    fn calculateIntrinsicCost(tx: transaction.Txn) u64 {
        var data_cost: u64 = 0;
        for (tx.data) |byte| {
            data_cost += if (byte == 0) TX_DATA_COST_PER_ZERO else TX_DATA_COST_PER_NON_ZERO;
        }

        const create_cost = if (tx.to == null) TX_CREATE_COST + initCodeCost(tx.data.len) else 0;

        const access_list_cost = switch (tx) {
            .LegacyTxn => 0,
            inline else => |al_tx| blk: {
                var sum: u64 = 0;
                for (al_tx.access_list) |al| {
                    data_cost += TX_ACCESS_LIST_ADDRESS_COST;
                    data_cost += al.storage_keys.len * TX_ACCESS_LIST_STORAGE_KEY_COST;
                }
                break :blk sum;
            },
        };

        return TX_BASE_COST + data_cost + create_cost + access_list_cost;
    }

    fn initCodeCost(code_length: usize) u64 {
        return GAS_INIT_CODE_WORD_COST * @ceil(code_length / 32);
    }

    pub const Message = struct {
        caller: Address,
        target: ?Address,
        current_target: Address,
        gas: u64,
        value: u256,
        data: []const u8,
        code_address: ?Address,
        code: []const u8,
        accessed_addresses: AddressSet,
        accessed_storage_keys: AddressKeySet,

        pub fn deinit(self: *Message) void {
            self.accessed_addresses.deinit();
            self.accessed_addresses = undefined;
            self.accessed_storage_keys.deinit();
            self.accessed_storage_keys = undefined;
        }
    };

    // prepareMessage prepares an EVM message.
    // The caller must call deinit() on the returned Message.
    fn prepareMessage(
        caller: Address,
        target: ?Address,
        value: u256,
        data: []const u8,
        gas: u64,
        env: Environment,
        code_address: ?Address,
        preaccessed_addresses: AddressSet,
        preaccessed_storage_keys: AddressKeySet,
    ) !Message {
        var current_target: Address = undefined;
        var msg_data: []const u8 = undefined;
        var code: []const u8 = undefined;

        if (target == null) {
            current_target = try computeContractAddress(caller, env.state.getAccount(caller).nonce - 1);
            msg_data = &[_]u8{0};
            code = data;
        } else {
            current_target = target;
            msg_data = data;
            code = env.state.getAccount(target).code;
            if (code_address == null)
                code_address = target;
        }

        var accessed_addresses = try preaccessed_addresses.clone();
        try accessed_addresses.put(current_target);
        try accessed_addresses.put(caller);
        for (PRE_COMPILED_CONTRACT_ADDRESSES) |address| {
            try accessed_addresses.put(address);
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
            .depth = 0,
            .accessed_addresses = accessed_addresses,
            .accessed_storage_keys = try preaccessed_storage_keys.clone(),
        };
    }

    fn computeContractAddress(allocator: Allocator, address: Address, nonce: u64) !Address {
        var out = std.ArrayList(u8).init(allocator);
        defer out.deinit();
        try rlp.serialize(struct { addr: Address, nonce: u64 }, allocator, .{ address, nonce }, out);
        const computed_address = std.crypto.hash.sha3.Keccak256(out.items);
        const canonical_address = computed_address[12..];
        var padded_address: Address = std.mem.zeroes(Address);
        @memcpy(padded_address[12..], canonical_address);
        return padded_address;
    }

    const MessageCallOutput = struct {
        gas_left: u64,
        refund_counter: u256,
        // logs: Union[Tuple[()], Tuple[Log, ...]] TODO
        // accounts_to_delete: AddressKeySet, // TODO (delete?)
        // touched_accounts: AddressKeySet, // TODO (delete?)
        // error: Optional[Exception] TODO
    };

    fn processMessageCall(message: Message, env: Environment) !MessageCallOutput {
        const vm_instance = VM.init(env);
        defer vm_instance.deinit();

        const result = try vm_instance.processMessageCall(message);
        defer result.release();
        return .{
            .gas_left = result.gas_left,
            .refund_counter = result.gas_refund,
            // .accounts_to_delete = AddressKeySet,
            // .touched_accounts = vm_instance.touched_accounts,
        };
    }
};
