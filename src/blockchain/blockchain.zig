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
pub const BlockHeader = types.BlockHeader;
const Environment = blockchain_types.Environment;
const Message = blockchain_types.Message;
const StateDB = @import("../state/state.zig").StateDB;
const Hash32 = types.Hash32;
const Bytes32 = types.Bytes32;
const Address = types.Address;
const Receipt = types.Receipt;
const Log = types.Log;
const LogArrayList = std.array_list.Managed(Log);
const TxSigner = signer.TxSigner;
const VM = vm.VM;
const Keccak256 = std.crypto.hash.sha3.Keccak256;
pub const Fork = @import("fork.zig");

pub const Blockchain = struct {
    allocator: Allocator,
    chain_id: config.ChainId,
    state: *StateDB,
    prev_block: BlockHeader,
    tx_signer: TxSigner,
    fork: *Fork,
    evmc_revision: u8 = 11,

    // init initializes a blockchain.
    // The caller **does not** transfer ownership of prev_block.
    pub fn init(
        allocator: Allocator,
        chain_id: config.ChainId,
        state: *StateDB,
        prev_block: BlockHeader,
        fork: *Fork,
    ) !Blockchain {
        return .{
            .allocator = allocator,
            .chain_id = chain_id,
            .state = state,
            .prev_block = try prev_block.clone(allocator),
            .fork = fork,
            .tx_signer = try signer.TxSigner.init(@intFromEnum(chain_id)),
        };
    }

    pub fn runBlock(self: *Blockchain, block: Block) !void {
        try validateBlockHeader(self.allocator, self.prev_block, block.header, self.evmc_revision);
        if (block.uncles.len != 0)
            return error.NotEmptyUncles;

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        // Note: state is NOT automatically rolled back on error.
        // Callers must handle state restoration externally if needed
        // (e.g., by re-creating the StateDB from genesis/preState).

        // Add the current block to the last 256 block hashes.
        try self.fork.update_parent_block_hash(block.header.block_number - 1, block.header.parent_hash);

        // Execute block.
        std.log.debug("runBlock: calling applyBody for block {d}", .{block.header.block_number});
        var result = try applyBody(allocator, self, self.state, block, self.tx_signer);
        std.log.debug("runBlock: applyBody done", .{});

        // Post execution checks.
        if (result.gas_used != block.header.gas_used) {
            std.log.err("gas_used mismatch in block {d}: got {d}, expected {d}, diff {d}", .{ block.header.block_number, result.gas_used, block.header.gas_used, @as(i64, @intCast(result.gas_used)) - @as(i64, @intCast(block.header.gas_used)) });
            return error.InvalidGasUsed;
        }
        if (!std.mem.eql(u8, &result.transactions_root, &block.header.transactions_root)) {
            std.log.err("transactions_root mismatch", .{});
            return error.InvalidTransactionsRoot;
        }
        if (!std.mem.eql(u8, &result.receipts_root, &block.header.receipts_root)) {
            std.log.err("receipts_root mismatch: got {x}, expected {x}", .{ &result.receipts_root, &block.header.receipts_root });
            return error.InvalidReceiptsRoot;
        }
        // TODO: disabled until state root is calculated
        // if (!std.mem.eql(u8, &self.state.root(), &block.header.state_root))
        //     return error.InvalidStateRoot;
        // TODO: disabled until logs bloom are calculated
        // if (!std.mem.eql(u8, &result.logs_bloom, &block.header.logs_bloom))
        //     return error.InvalidLogsBloom;
        if (block.header.withdrawals_root) |wr| {
            if (result.withdrawals_root) |rwr| {
                if (!std.mem.eql(u8, &rwr, &wr)) {
                    std.log.err("withdrawals_root mismatch", .{});
                    return error.InvalidWithdrawalsRoot;
                }
            }
        }

        // Note that we free and clone with the Blockchain allocator, and not the arena allocator.
        // This is required since Blockchain field lifetimes are longer than the block execution processing.
        self.prev_block.deinit(self.allocator);
        self.prev_block = try block.header.clone(self.allocator);
    }

    // validateBlockHeader validates the header of a block itself and with respect with the parent.
    // If isn't valid, it returns an error.
    fn validateBlockHeader(allocator: Allocator, prev_block: BlockHeader, curr_block: BlockHeader, evmc_revision: u8) !void {
        try checkGasLimit(curr_block.gas_limit, prev_block.gas_limit);
        if (curr_block.gas_used > curr_block.gas_limit)
            return error.GasLimitExceeded;

        // Check base fee (EIP-1559, London+).
        if (prev_block.base_fee_per_gas != null or curr_block.base_fee_per_gas != null) {
            const parent_gas_target = prev_block.gas_limit / params.elasticity_multiplier;
            const expected_base_fee_per_gas = if (prev_block.gas_used == parent_gas_target)
                prev_block.base_fee_per_gas
            else if (prev_block.gas_used > parent_gas_target) blk: {
                const gas_used_delta = prev_block.gas_used - parent_gas_target;
                const base_fee_per_gas_delta = @max(prev_block.base_fee_per_gas.? * gas_used_delta / parent_gas_target / params.base_fee_max_change_denominator, 1);
                break :blk prev_block.base_fee_per_gas.? + base_fee_per_gas_delta;
            } else blk: {
                const gas_used_delta = parent_gas_target - prev_block.gas_used;
                const base_fee_per_gas_delta = prev_block.base_fee_per_gas.? * gas_used_delta / parent_gas_target / params.base_fee_max_change_denominator;
                break :blk prev_block.base_fee_per_gas.? - base_fee_per_gas_delta;
            };
            const expected_val = expected_base_fee_per_gas orelse 0;
            const actual_val = curr_block.base_fee_per_gas orelse 0;
            if (expected_val != actual_val)
                return error.InvalidBaseFee;
        }

        if (curr_block.timestamp <= prev_block.timestamp)
            return error.InvalidTimestamp;
        if (curr_block.block_number != prev_block.block_number + 1)
            return error.InvalidBlockNumber;
        if (curr_block.extra_data.len > 32)
            return error.ExtraDataTooLong;

        // Post-Merge (Paris+) checks: difficulty and nonce must be zero
        if (evmc_revision >= 10) { // EVMC_PARIS = 10
            if (curr_block.difficulty != 0)
                return error.InvalidDifficulty;
            if (!std.mem.eql(u8, &curr_block.nonce, &[_]u8{0} ** 8))
                return error.InvalidNonce;
            if (!std.mem.eql(u8, &curr_block.uncle_hash, &blocks.empty_uncle_hash))
                return error.InvalidUnclesHash;
        }

        const prev_block_hash = try common.encodeToRLPAndHash(BlockHeader, allocator, prev_block, null);
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
        withdrawals_root: ?Hash32,
    };

    fn applyBody(allocator: Allocator, chain: *Blockchain, state: *StateDB, block: Block, tx_signer: TxSigner) !BlockExecutionResult {
        std.log.debug("applyBody: start block {d}, {d} txs", .{block.header.block_number, block.transactions.len});
        var gas_available = block.header.gas_limit;

        var receipts = try allocator.alloc(Receipt, block.transactions.len);
        defer allocator.free(receipts);

        // EIP-4788: Beacon block root system call (Cancun+)
        if (block.header.parent_beacon_root) |parent_beacon_root| {
            try state.startTx();
            const beacon_root_addr: Address = .{ 0x00, 0x0f, 0x3d, 0xf6, 0xd7, 0x32, 0x80, 0x7e, 0xf1, 0x31, 0x9f, 0xb7, 0xb8, 0xbb, 0x85, 0x22, 0xd0, 0xbe, 0xac, 0x02 };
            const system_addr: Address = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };

            // Call the beacon root contract with timestamp as input
            var timestamp_input: [32]u8 = std.mem.zeroes([32]u8);
            std.mem.writeInt(u256, &timestamp_input, block.header.timestamp, .big);

            const sys_env: Environment = .{
                .fork = chain.fork,
                .origin = system_addr,
                .coinbase = block.header.fee_recipient,
                .number = block.header.block_number,
                .gas_limit = block.header.gas_limit,
                .base_fee_per_gas = block.header.base_fee_per_gas orelse 0,
                .gas_price = 0,
                .time = block.header.timestamp,
                .prev_randao = block.header.prev_randao,
                .state = state,
                .chain_id = chain.chain_id,
                .evmc_revision = chain.evmc_revision,
            };

            // Ensure system address exists
            if (state.getAccountOpt(system_addr) == null) {
                try state.setBalance(system_addr, 0);
            }

            const sys_msg: Message = .{
                .sender = system_addr,
                .target = beacon_root_addr,
                .gas = 30_000_000,
                .value = 0,
                .data = &parent_beacon_root,
            };

            var vm_instance = VM.init(allocator, sys_env);
            defer vm_instance.deinit();
            _ = try vm_instance.processMessageCall(sys_msg);

            // Remove system address if empty (EIP-4788 spec)
            if (state.accountExistsAndIsEmpty(system_addr)) {
                state.destroyAccount(system_addr);
            }
        }

        // EIP-4844: compute blob base fee from excess blob gas
        const blob_base_fee: u256 = if (block.header.excess_blob_gas) |ebg|
            calcBlobBaseFee(ebg)
        else
            0;
        var total_blob_gas: u64 = 0;

        for (block.transactions, 0..) |tx, i| {
            const tx_info = try checkTransaction(allocator, tx, block.header.base_fee_per_gas orelse 0, gas_available, tx_signer);

            // EIP-4844: validate max_fee_per_blob_gas >= blob_base_fee
            if (tx == .BlobTx) {
                if (tx.BlobTx.max_fee_per_blob_gas < blob_base_fee)
                    return error.MaxFeePerBlobGasTooLow;
                total_blob_gas += tx.BlobTx.totalBlobGas();
            }

            const env: Environment = .{
                .fork = chain.fork,
                .origin = tx_info.sender_address,
                .coinbase = block.header.fee_recipient,
                .number = block.header.block_number,
                .gas_limit = block.header.gas_limit,
                .base_fee_per_gas = block.header.base_fee_per_gas orelse 0,
                .gas_price = tx_info.effective_gas_price,
                .time = block.header.timestamp,
                .prev_randao = block.header.prev_randao,
                .state = state,
                .chain_id = chain.chain_id,
                .evmc_revision = chain.evmc_revision,
                .blob_base_fee = blob_base_fee,
                .blob_hashes = tx.getBlobVersionedHashes(),
            };

            std.log.debug("applyBody: processing tx {d}", .{i});
            const exec_tx_result = try processTransaction(allocator, env, tx);
            std.log.debug("applyBody: blk {d} tx {d} done, gas_used={d}, gas_limit={d}", .{ block.header.block_number, i, exec_tx_result.gas_used, tx.getGasLimit() });
            gas_available -= exec_tx_result.gas_used;

            // Create receipt.
            const cumm_gas_used = block.header.gas_limit - gas_available;
            var receipt = Receipt.init(exec_tx_result.success, cumm_gas_used, @constCast(exec_tx_result.logs));
            receipt.tx_type = switch (tx) {
                .LegacyTx => 0,
                .AccessListTx => 1,
                .FeeMarketTx => 2,
                .BlobTx => 3,
                .SetCodeTx => 4,
            };
            receipts[i] = receipt;

            // TODO: do tx logs aggregation.
        }

        std.log.debug("applyBody: all txs done, computing roots", .{});
        const block_gas_used = block.header.gas_limit - gas_available;

        // TODO: logs bloom calculation.

        // Block reward for pre-Merge (pre-Paris) forks
        if (chain.evmc_revision < 10) { // EVMC_PARIS = 10
            const block_reward: u256 = if (chain.evmc_revision < 6) // Pre-Constantinople
                5000000000000000000 // 5 ETH
            else if (chain.evmc_revision < 8) // Pre-Istanbul (Constantinople/Petersburg)
                3000000000000000000 // 3 ETH
            else
                2000000000000000000; // 2 ETH (post-Constantinople)
            const coinbase_balance = state.getAccount(block.header.fee_recipient).balance;
            try state.setBalance(block.header.fee_recipient, coinbase_balance + block_reward);
        }

        for (block.withdrawals orelse &.{}) |w| {
            const newBalance = state.getAccount(w.address).balance + (w.amount * std.math.pow(u256, 10, 9));
            try state.setBalance(w.address, newBalance);
        }

        return .{
            .gas_used = block_gas_used,
            .transactions_root = try calculateMPTRoot(allocator, block.transactions),
            .receipts_root = try calculateMPTRoot(allocator, receipts),
            .logs_bloom = block.header.logs_bloom,
            .withdrawals_root = if (block.withdrawals) |w| try calculateMPTRoot(allocator, w) else null,
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
            const encoded_item = try items[0].encode(arena);
            keyvals[i] = try mpt.KeyVal.init(arena, &[_]u8{0x80}, encoded_item);
            i += 1;
        }

        while (i < items.len) : (i += 1) {
            var out = std.array_list.Managed(u8).init(arena);
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
            inline .FeeMarketTx, .BlobTx, .SetCodeTx => |fm_tx| blk: {
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

    fn processTransaction(allocator: Allocator, env: Environment, tx: transaction.Tx) !struct { success: bool, gas_used: u64, logs: []const Log } {
        if (!validateTransaction(tx, env.evmc_revision))
            return error.InvalidTransaction;

        // Start a new transaction context (must be after validation to avoid state corruption on invalid txs)
        try env.state.startTx();

        const sender = env.origin;

        const gas_fee = tx.getGasLimit() * tx.getGasPrice();

        var sender_account = env.state.getAccount(sender);
        if (sender_account.nonce != tx.getNonce())
            return error.InvalidTxNonce;
        // Include blob gas cost in balance check (EIP-4844)
        const blob_gas_cost: u256 = if (tx == .BlobTx)
            tx.BlobTx.totalBlobGas() * env.blob_base_fee
        else
            0;
        if (sender_account.balance < gas_fee + tx.getValue() + blob_gas_cost) {
            std.log.err("NotEnoughBalance: sender={x} balance={d}, gas_fee={d}, value={d}, total_needed={d}, nonce={d}", .{ &env.origin, sender_account.balance, gas_fee, tx.getValue(), gas_fee + tx.getValue() + blob_gas_cost, sender_account.nonce });
            return error.NotEnoughBalance;
        }
        // EIP-7702: sender with delegation code (0xef0100 prefix) is treated as EOA.
        if (sender_account.code.len > 0) {
            if (sender_account.code.len != 23 or !std.mem.eql(u8, sender_account.code[0..3], &params.delegation_magic))
                return error.SenderIsNotEOA;
        }

        const gas = tx.getGasLimit() - calculateIntrinsicCost(tx);
        const effective_gas_fee = tx.getGasLimit() * env.gas_price;

        const sender_balance_after_gas_fee = sender_account.balance - effective_gas_fee - blob_gas_cost;
        try env.state.setBalance(sender, sender_balance_after_gas_fee);

        // Increment sender nonce for non-CREATE txs (must happen before EIP-7702
        // authorization processing, since self-sponsored txs check authority nonce
        // after sender nonce increment). CREATE nonce is handled in processMessageCall.
        if (tx.getTo() != null) {
            try env.state.incrementNonce(sender);
        }

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

        // EIP-2929: warm sender, recipient, coinbase, and precompiles
        try env.state.putAccessedAccount(sender);
        if (tx.getTo()) |to| {
            try env.state.putAccessedAccount(to);
        }
        for (params.precompiled_contract_addresses) |precompile_addr| {
            try env.state.putAccessedAccount(precompile_addr);
        }

        // EIP-7702: Process authorization list (SetCode tx).
        // For each authorization, recover the authority, validate, set delegation code.
        var auth_refund: u64 = 0;
        if (tx == .SetCodeTx) {
            const ecdsa_signer = @import("../crypto/crypto.zig").ecdsa.Signer.init() catch unreachable;
            for (tx.SetCodeTx.authorization_list) |auth| {
                // EIP-2681: nonce must not overflow u64. Check BEFORE ecrecover.
                if (auth.nonce == std.math.maxInt(u64)) continue;

                // Recover authority address from authorization signature.
                const authority = recoverAuthority(allocator, ecdsa_signer, auth, @intFromEnum(env.chain_id)) catch |err| {
                    std.log.debug("EIP-7702: auth recovery failed: {}", .{err});
                    continue;
                };

                // Check if authority exists BEFORE adding to access list (for refund calc).
                const authority_exists = env.state.getAccountOpt(authority) != null;

                // Add authority to accessed addresses (even if auth is invalid, per EIP-7702).
                try env.state.putAccessedAccount(authority);

                // Verify authority code is empty or already a delegation.
                const authority_account = env.state.getAccount(authority);
                if (authority_account.code.len > 0) {
                    if (authority_account.code.len != 23) continue;
                    if (!std.mem.eql(u8, authority_account.code[0..3], &params.delegation_magic)) continue;
                }

                // Verify authority nonce matches.
                if (authority_account.nonce != auth.nonce) continue;

                // If authority already exists in state, refund the new account cost difference.
                // Intrinsic gas charges CallNewAccountGas (25000), but existing accounts
                // only need TxAuthTupleGas (12500), so refund the difference.
                if (authority_exists) {
                    auth_refund += params.per_auth_base_cost - params.tx_auth_tuple_gas;
                }

                // Increment authority nonce.
                try env.state.incrementNonce(authority);

                // EIP-7702: if auth.address is zero, clear the delegation (reset to EOA).
                // Otherwise, set delegation code: 0xef0100 || address.
                const zero_addr: Address = .{0} ** 20;
                if (std.mem.eql(u8, &auth.address, &zero_addr)) {
                    try env.state.setDelegationCode(authority, &.{});
                    std.log.debug("EIP-7702: cleared delegation on 0x{x}", .{authority});
                } else {
                    var delegation_code: [23]u8 = undefined;
                    @memcpy(delegation_code[0..3], &params.delegation_magic);
                    @memcpy(delegation_code[3..23], &auth.address);
                    try env.state.setDelegationCode(authority, &delegation_code);
                    std.log.debug("EIP-7702: set delegation on 0x{x} -> 0x{x}", .{ authority, auth.address });
                }
            }
        }

        const message: Message = .{
            .sender = sender,
            .target = tx.getTo(),
            .gas = gas,
            .value = tx.getValue(),
            .data = tx.getData(),
        };
        var logs_list = LogArrayList.init(allocator);
        var env_with_logs = env;
        env_with_logs.logs = &logs_list;
        const output = try processMessageCall(allocator, message, env_with_logs);

        const gas_used = tx.getGasLimit() - output.gas_left;
        const gas_refund = @min(gas_used / 5, output.refund_counter + auth_refund);
        const standard_gas_used = gas_used - gas_refund;

        // EIP-7623 (Prague+): floor cost for calldata-heavy transactions.
        // gas_used = max(standard_gas_used, floor_cost)
        // floor_cost is capped at gas_limit since gas_used can never exceed gas_limit.
        const total_gas_used = if (env.evmc_revision >= 13)
            @min(tx.getGasLimit(), @max(standard_gas_used, calculateFloorCost(tx)))
        else
            standard_gas_used;

        const gas_refund_amount = (tx.getGasLimit() - total_gas_used) * env.gas_price;

        const priority_fee_per_gas = env.gas_price - env.base_fee_per_gas;
        const transaction_fee = total_gas_used * priority_fee_per_gas;

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

        // EIP-6780: destroy accounts that selfdestructed and were created in same tx
        var destroy_it = env.state.accounts_to_destroy.keyIterator();
        while (destroy_it.next()) |addr| {
            env.state.destroyAccount(addr.*);
        }

        for (env.state.touched_addresses.items) |address| {
            if (env.state.isEmpty(address))
                env.state.destroyAccount(address);
        }

        return .{ .success = output.success, .gas_used = total_gas_used, .logs = output.logs };
    }

    fn validateTransaction(tx: transaction.Tx, evmc_revision: u8) bool {
        // Validate tx type is allowed for this fork
        switch (tx) {
            .AccessListTx => if (evmc_revision < 8) return false, // EVMC_BERLIN = 8
            .FeeMarketTx => if (evmc_revision < 9) return false, // EVMC_LONDON = 9
            .BlobTx => if (evmc_revision < 12) return false, // EVMC_CANCUN = 12
            .SetCodeTx => if (evmc_revision < 13) return false, // EVMC_PRAGUE = 13
            .LegacyTx => {},
        }
        // Intrinsic gas check (always).
        const min_gas = calculateIntrinsicCost(tx);
        if (min_gas > tx.getGasLimit())
            return false;
        if (tx.getNonce() >= (2 << 64) - 1)
            return false;
        if (tx.getTo() == null and tx.getData().len > 2 * params.max_code_size)
            return false;
        // EIP-4844: blob tx must not be a contract creation and must have at least one blob
        if (tx == .BlobTx) {
            if (tx.getTo() == null) return false;
            if (tx.BlobTx.blob_versioned_hashes.len == 0) return false;
            // Validate versioned hash prefixes (must be 0x01)
            for (tx.BlobTx.blob_versioned_hashes) |h| {
                if (h[0] != 0x01) return false;
            }
        }
        // EIP-7702: SetCode tx must have a non-empty authorization list
        if (tx == .SetCodeTx) {
            if (tx.SetCodeTx.authorization_list.len == 0) return false;
        }
        return true;
    }

    fn calldataTokens(tx: transaction.Tx) u64 {
        var tokens: u64 = 0;
        for (tx.getData()) |byte| {
            tokens += if (byte == 0) params.tx_tokens_per_zero_byte else params.tx_tokens_per_non_zero_byte;
        }
        return tokens;
    }

    fn calculateIntrinsicCost(tx: transaction.Tx) u64 {
        var data_cost: u64 = 0;
        for (tx.getData()) |byte| {
            data_cost += if (byte == 0) params.tx_data_cost_per_zero else params.tx_data_cost_per_non_zero;
        }

        const create_cost = if (tx.getTo() == null) params.tx_create_cost + initCodeCost(tx.getData().len) else 0;

        var access_list_cost: u64 = 0;
        switch (tx) {
            .LegacyTx => {},
            inline else => |al_tx| {
                for (al_tx.access_list) |al| {
                    access_list_cost += params.tx_access_list_address_cost;
                    access_list_cost += al.storage_keys.len * params.tx_access_list_storage_key_cost;
                }
            },
        }

        // EIP-7702: authorization list cost
        const auth_cost = tx.getAuthorizationList().len * params.per_auth_base_cost;

        return params.tx_base_cost + data_cost + create_cost + access_list_cost + auth_cost;
    }

    /// EIP-7623: floor cost for calldata-heavy transactions (Prague+).
    /// Floor = 21000 + TOTAL_COST_FLOOR_PER_TOKEN * tokens + CREATE_GAS (if contract creation).
    /// Per EIP-7623, access list cost is NOT included in the floor.
    fn calculateFloorCost(tx: transaction.Tx) u64 {
        const tokens = calldataTokens(tx);
        const create_cost = if (tx.getTo() == null) params.tx_create_cost + initCodeCost(tx.getData().len) else 0;
        return params.tx_base_cost + tokens * params.tx_total_cost_floor_per_token + create_cost;
    }

    /// Recover the authority address from an EIP-7702 authorization tuple.
    /// Signing hash: keccak256(0x05 || rlp([chain_id, address, nonce]))
    fn recoverAuthority(allocator: Allocator, ecdsa_signer: @import("../crypto/crypto.zig").ecdsa.Signer, auth: transaction.Authorization, chain_id: u64) !Address {
        // Validate chain_id: must be 0 (any chain) or match current chain.
        if (auth.chain_id != 0 and auth.chain_id != chain_id)
            return error.InvalidAuthChainId;

        // Validate signature fields.
        @import("../crypto/crypto.zig").ecdsa.validateSignatureFields(auth.r, auth.s) catch
            return error.InvalidAuthSignature;

        // Build signing payload: 0x05 || rlp([chain_id, address, nonce])
        const AuthRLP = struct {
            chain_id: u64,
            address: Address,
            nonce: u64,
        };
        var out = std.array_list.Managed(u8).init(allocator);
        defer out.deinit();
        try rlp.serialize(AuthRLP, allocator, .{
            .chain_id = auth.chain_id,
            .address = auth.address,
            .nonce = auth.nonce,
        }, &out);

        const hasher = @import("../crypto/crypto.zig").hasher;
        const auth_hash = try hasher.keccak256WithPrefix(&[_]u8{0x05}, out.items);

        // Recover public key from signature.
        var sig: [65]u8 = undefined;
        std.mem.writeInt(u256, sig[0..32], auth.r, .big);
        std.mem.writeInt(u256, sig[32..64], auth.s, .big);
        sig[64] = @intCast(auth.y_parity);

        const pubkey = try ecdsa_signer.erecover(sig, auth_hash);
        return hasher.keccak256(pubkey[1..])[12..].*;
    }

    fn initCodeCost(code_length: usize) u64 {
        return params.gas_init_code_word_const * ((code_length + 31) / 32);
    }

    fn processMessageCall(allocator: Allocator, message: Message, env: Environment) !vm.MessageCallOutput {
        var vm_instance = VM.init(allocator, env);
        defer vm_instance.deinit();

        return try vm_instance.processMessageCall(message);
    }

    /// EIP-4844: Calculate the blob base fee from excess blob gas.
    /// Uses the fake exponential: fake_exponential(1, excess_blob_gas, blob_base_fee_update_fraction)
    fn calcBlobBaseFee(excess_blob_gas: u64) u256 {
        if (excess_blob_gas == 0) return params.min_blob_base_fee;
        // fake_exponential(factor=1, numerator=excess_blob_gas, denominator=blob_base_fee_update_fraction)
        // = sum_{i=0..} (factor * numerator^i) / (denominator^i * i!)
        // Iterative computation until term becomes zero
        var result: u256 = 0;
        var numerator_accum: u256 = params.blob_base_fee_update_fraction; // denominator * factor
        const numerator: u256 = excess_blob_gas;
        const denominator: u256 = params.blob_base_fee_update_fraction;
        var i: u256 = 1;
        while (numerator_accum > 0) {
            result += numerator_accum;
            numerator_accum = numerator_accum * numerator / (denominator * i);
            i += 1;
        }
        return @max(result / denominator, params.min_blob_base_fee);
    }

    /// EIP-4844: Calculate excess blob gas for the current block.
    fn calcExcessBlobGas(parent_excess_blob_gas: u64, parent_blob_gas_used: u64) u64 {
        const total = parent_excess_blob_gas + parent_blob_gas_used;
        if (total < params.target_blob_gas_per_block) return 0;
        return total - params.target_blob_gas_per_block;
    }
};
