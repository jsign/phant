const evmc = @cImport({
    @cInclude("evmone.h");
});
const std = @import("std");
const util = @import("util.zig");
const types = @import("../types/types.zig");
const Transaction = types.Transaction;
const Block = types.Block;
const AccountState = types.AccountState;
const Bytecode = types.Bytecode;
const Address = types.Address;
const assert = std.debug.assert;
const log = std.log.scoped(.vm);

pub const StateDB = @import("statedb.zig");

const txn_base_gas = 21_000;

// ExecutionContext describes the current execution context of the VM.
const ExecutionContext = struct {
    // address is the current address used for storage access.
    address: Address,
};

pub const VM = struct {
    // statedb is the state database.
    statedb: *StateDB,
    // host is the EVMC host interface.
    host: evmc.struct_evmc_host_interface,
    // evm is the EVMC implementation.
    evm: [*c]evmc.evmc_vm,

    // exec_context has the current execution context.
    exec_context: ?ExecutionContext,
    // tx_context for the current execution.
    tx_context: ?evmc.struct_evmc_tx_context,

    pub fn init(statedb: *StateDB) VM {
        var evm = evmc.evmc_create_evmone();
        log.info(
            "evmone info: name={s}, version={s}, abi_version={d}",
            .{ evm.*.name, evm.*.version, evm.*.abi_version },
        );
        return VM{
            .statedb = statedb,
            .host = evmc.struct_evmc_host_interface{
                .account_exists = account_exists,
                .get_storage = get_storage,
                .set_storage = set_storage,
                .get_balance = get_balance,
                .get_code_size = get_code_size,
                .get_code_hash = get_code_hash,
                .copy_code = copy_code,
                .selfdestruct = self_destruct,
                .call = call,
                .get_tx_context = get_tx_context,
                .get_block_hash = get_block_hash,
                .emit_log = emit_log,
                .access_account = access_account,
                .access_storage = access_storage,
            },
            .evm = evm,
            .exec_context = null,
            .tx_context = null,
        };
    }

    pub fn deinit() void {
        // TODO(jsign): check freeing evmone instance.
    }

    pub fn run_block(self: *VM, block: Block, txns: []const Transaction) !void {
        log.debug("run block number={d}", .{block.header.block_number});
        // TODO: stashing area.
        for (txns) |txn| {
            // TODO(jsign): check why we need @intCast(), as in, why EVMC expects signed integers?
            self.tx_context = evmc.struct_evmc_tx_context{
                .tx_gas_price = util.to_evmc_bytes32(txn.gas_price),
                .tx_origin = util.to_evmc_address(txn.get_from()),
                .block_coinbase = .{ .bytes = block.header.fee_recipient },
                .block_number = @intCast(block.header.block_number),
                .block_timestamp = @intCast(block.header.timestamp),
                .block_gas_limit = @intCast(block.header.gas_limit),
                .block_prev_randao = .{ .bytes = block.header.prev_randao },
                .chain_id = util.to_evmc_bytes32(txn.chain_id),
                .block_base_fee = .{ .bytes = [_]u8{0} ** (32 - 4) ++ block.header.base_fee_per_gas }, // TODO(jsign): check this.
                .blob_hashes = null, // TODO
                .blob_hashes_count = 0, // TODO
            };
            try self.run_txn(txn);
        }

        self.tx_context = null;
        self.exec_context = null;
    }

    // TODO(jsign): remove this method.
    pub fn run_txns(self: *VM, txns: []const Transaction) void {
        // TODO: stashing area.
        for (txns) |txn| {
            self.run_txn(txn);
        }
    }

    fn run_txn(self: *VM, txn: Transaction) !void {
        var remaining_gas: i64 = @intCast(txn.gas_limit);

        if (txn.to) |to| {
            assert(!std.mem.eql(u8, &to, &std.mem.zeroes(Address)));
            var account = try self.statedb.get(to);

            if (txn.nonce +% 1 < txn.nonce) {
                return error.MaxNonce;
            }
            if (txn.nonce != account.nonce) {
                log.err("txn nonce {d} != account nonce {d}", .{ txn.nonce, account.nonce });
                return error.InvalidNonce;
            }

            if (txn.value > 0) { // TODO(jsign): incomplete
                account.balance += txn.value;
            }

            // TODO(jsign): this is incomplete.
            try charge_gas(&remaining_gas, txn_base_gas);

            // Contract call
            const recipient_code = account.code;
            if (recipient_code.len != 0) {
                const message = evmc.struct_evmc_message{
                    .kind = evmc.EVMC_CALL, // TODO(jsign): generalize.
                    .flags = 0, // TODO: STATIC?
                    .depth = 0,
                    .gas = @intCast(remaining_gas), // TODO(jsign): why evmc expects a i64 for gas instead of u64?
                    .recipient = util.to_evmc_address(txn.to),
                    .sender = util.to_evmc_address(txn.get_from()),
                    .input_data = txn.data.ptr,
                    .input_size = txn.data.len,
                    .value = blk: {
                        var txn_value: [32]u8 = undefined;
                        std.mem.writeIntSliceBig(u256, &txn_value, txn.value);
                        break :blk .{ .bytes = txn_value };
                    },
                    .create2_salt = .{
                        .bytes = [_]u8{0} ** 32, // TODO: fix this.
                    },
                    .code_address = util.to_evmc_address(txn.to), // TODO: fix this when .kind is generalized.
                };
                log.debug(
                    "executing transaction sender={} receipient={}",
                    .{
                        std.fmt.fmtSliceHexLower(&message.sender.bytes),
                        std.fmt.fmtSliceHexLower(&message.recipient.bytes),
                    },
                ); // TODO(jsign): add txn hash when available.

                // Initialize the execution context.
                self.exec_context = ExecutionContext{
                    .address = txn.get_from(),
                };
                log.warn("COOODE {}", .{std.fmt.fmtSliceHexLower(recipient_code)});

                // TODO(jsign): EVMC_SHANGHAI should be configurable at runtime.
                var result = self.evm.*.execute.?(
                    self.evm,
                    @ptrCast(&self.host),
                    @ptrCast(self),
                    evmc.EVMC_SHANGHAI,
                    @ptrCast(&message),
                    recipient_code.ptr,
                    recipient_code.len,
                );
                log.debug("execution result: status_code={}, gas_left={}", .{ result.status_code, result.gas_left });

                remaining_gas = result.gas_left + result.gas_refund;
            }
        } else { // Contract creation.
            @panic("TODO contract creation");
        }

        const gas_price = 0xa - 0x7; // TODO(jsign): fix, pull from tx_context.
        const gas_used = @as(i64, @intCast(txn.gas_limit)) - remaining_gas; // TODO(jsign): decide on casts.
        log.info("gas used {x}", .{gas_used});
        const fee = gas_used * gas_price;
        try self.statedb.add_balance(self.tx_context.?.block_coinbase.bytes, @as(u256, @intCast(fee)));
    }

    inline fn charge_gas(remaining_gas: *i64, charge: u64) !void {
        if (remaining_gas.* < charge) {
            return error.OutOfGas;
        }
        remaining_gas.* -= charge;
    }

    // ### EVMC Host Interface ###

    fn get_tx_context(ctx: ?*evmc.struct_evmc_host_context) callconv(.C) evmc.struct_evmc_tx_context {
        log.debug("get_tx_context()", .{});
        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        return vm.tx_context.?;
    }

    fn get_block_hash(
        ctx: ?*evmc.struct_evmc_host_context,
        xx: i64,
    ) callconv(.C) evmc.evmc_bytes32 {
        _ = xx;
        _ = ctx;
        @panic("TODO");
    }

    fn account_exists(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
    ) callconv(.C) bool {
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn get_storage(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        dest: [*c]const evmc.evmc_bytes32,
    ) callconv(.C) evmc.evmc_bytes32 {
        _ = ctx;
        _ = dest;
        _ = addr;
        @panic("TODO");
    }
    fn set_storage(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        value: [*c]const evmc.evmc_bytes32,
        xxx: [*c]const evmc.evmc_bytes32,
    ) callconv(.C) evmc.enum_evmc_storage_status {
        _ = xxx;
        _ = value;
        _ = addr;
        _ = ctx;
        return evmc.EVMC_STORAGE_ADDED; // TODO(jsign): fix
    }

    fn get_balance(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
    ) callconv(.C) evmc.evmc_uint256be {
        _ = ctx;
        const addr_hex = std.fmt.bytesToHex(addr.*.bytes, std.fmt.Case.lower);
        log.debug("evmc call -> getBalance(0x{s})", .{addr_hex});

        var beval: [32]u8 = undefined;
        std.mem.writeIntSliceBig(u256, &beval, 142);

        return evmc.evmc_uint256be{
            .bytes = beval,
        };
    }

    fn get_code_size(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
    ) callconv(.C) usize {
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn get_code_hash(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
    ) callconv(.C) evmc.evmc_bytes32 {
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn copy_code(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        xxx: usize,
        xxy: [*c]u8,
        xxz: usize,
    ) callconv(.C) usize {
        _ = xxz;
        _ = xxy;
        _ = xxx;
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn self_destruct(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        addr2: [*c]const evmc.evmc_address,
    ) callconv(.C) bool {
        _ = addr2;
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn emit_log(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        xxx: [*c]const u8,
        xxy: usize,
        xxz: [*c]const evmc.evmc_bytes32,
        xxxzz: usize,
    ) callconv(.C) void {
        _ = xxxzz;
        _ = xxz;
        _ = xxy;
        _ = xxx;
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn access_account(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
    ) callconv(.C) evmc.enum_evmc_access_status {
        log.debug("access_account(addr={})", .{std.fmt.fmtSliceHexLower(&addr.*.bytes)});
        _ = ctx;
        return evmc.EVMC_ACCESS_COLD;
    }

    fn access_storage(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        value: [*c]const evmc.evmc_bytes32,
    ) callconv(.C) evmc.enum_evmc_access_status {
        _ = value;
        _ = addr;
        _ = ctx;
        return evmc.EVMC_ACCESS_COLD; // TODO(jsign): fix
    }

    fn call(
        ctx: ?*evmc.struct_evmc_host_context,
        msg: [*c]const evmc.struct_evmc_message,
    ) callconv(.C) evmc.struct_evmc_result {
        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        log.debug(
            "call depth={d} sender={} recipient={}",
            .{
                msg.*.depth,
                std.fmt.fmtSliceHexLower(&msg.*.sender.bytes),
                std.fmt.fmtSliceHexLower(&msg.*.recipient.bytes),
            },
        ); // TODO(jsign): explore creating custom formatter?

        // Check if the target address is a contract, and do the appropiate call.
        const recipient_account = vm.statedb.get(util.from_evmc_address(msg.*.code_address)) catch unreachable; // TODO(jsign): fix this.
        if (recipient_account.code.len != 0) {
            log.debug("contract call, codelen={d}", .{recipient_account.code.len});
            // Persist the current context. We'll restore it after the call returns.
            const prev_context = vm.*.exec_context.?;

            // Create the new context to be used to do the call.
            vm.exec_context = ExecutionContext{ .address = util.from_evmc_address(msg.*.recipient) };

            // TODO(jsign): EVMC_SHANGHAI should be configurable at runtime.
            var result = vm.evm.*.execute.?(
                vm.evm,
                @ptrCast(&vm.host),
                @ptrCast(vm),
                evmc.EVMC_SHANGHAI,
                msg,
                recipient_account.code.ptr,
                recipient_account.code.len,
            );
            log.debug(
                "internal call exec result: status_code={}, gas_left={}",
                .{ result.status_code, result.gas_left },
            );

            // Restore previous context after call() returned.
            vm.exec_context = prev_context;

            return result;
        }

        log.debug("non-contract call", .{});
        // TODO(jsign): verify.
        return evmc.evmc_result{
            .status_code = evmc.EVMC_SUCCESS,
            .gas_left = msg.*.gas, // TODO: fix
            .gas_refund = 0,
            .output_data = null,
            .output_size = 0,
            .release = null,
            .create_address = std.mem.zeroes(evmc.evmc_address),
            .padding = [_]u8{0} ** 4,
        };
    }
};
