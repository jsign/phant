const evmc = @cImport({
    @cInclude("evmone.h");
});
const std = @import("std");
const Allocator = std.mem.Allocator;
const util = @import("util.zig");
const types = @import("../types/types.zig");
const Txn = types.Txn;
const TxnSigner = @import("../signer/signer.zig").TxnSigner;
const Block = types.Block;
const AccountState = types.AccountState;
const Bytecode = types.Bytecode;
const Address = types.Address;
const assert = std.debug.assert;
const log = std.log.scoped(.vm);

pub const StateDB = @import("statedb.zig");

const txn_base_gas = 21_000;

const ExecutionContext = struct {
    // storage_address is the current address used for storage access.
    storage_address: Address,
};

const TxnContext = struct {
    chain_id: u256,
    gas_price: u256,
    from: Address,
};

const BlockContext = struct {
    coinbase: Address,
    number: u64,
    timestamp: u64,
    gas_limit: u64,
    prev_randao: u256,
    base_fee: u256,
};

pub const VM = struct {
    // statedb is the state database.
    statedb: *StateDB,
    // host is the EVMC host interface.
    host: evmc.struct_evmc_host_interface,
    // evm is the EVMC implementation.
    evm: [*c]evmc.evmc_vm,

    // exec_context has the current execution context.
    context: ?struct {
        execution: ExecutionContext,
        txn: TxnContext,
        block: BlockContext,
    },

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
            .context = null,
        };
    }

    pub fn deinit() void {
        // TODO(jsign): check freeing evmone instance.
    }

    fn processMessage(self: *VM, msg: Message) !void {
        const from_addr = self.*.context.?.txn.from;

        var remaining_gas: i64 = @intCast(txn.getGasLimit());

        // Sender nonce updating.
        if (txn.getNonce() +% 1 < txn.getNonce()) {
            return error.MaxNonce;
        }
        try self.statedb.incrementNonce(from_addr);

        // Charge intrinsic gas costs.
        // TODO(jsign): this is incomplete.
        try charge_gas(&remaining_gas, txn_base_gas);

        if (txn.getTo()) |to_addr| {
            assert(!std.mem.eql(u8, &to_addr, &std.mem.zeroes(Address)));

            // Send transaction value to the recipient.
            if (txn.getValue() > 0) { // TODO(jsign): incomplete
                try self.statedb.setBalance(to_addr, txn.getValue()); // TODO: TEMP wrong
            }

            self.context.?.execution = ExecutionContext{
                .storage_address = from_addr,
            };
            const msg = evmc.struct_evmc_message{
                .kind = evmc.EVMC_CALL, // TODO(jsign): generalize.
                .flags = 0, // TODO: STATIC?
                .depth = 0,
                .gas = @intCast(remaining_gas), // TODO(jsign): why evmc expects a i64 for gas instead of u64?
                .recipient = util.to_evmc_address(txn.getTo()),
                .sender = util.to_evmc_address(from_addr),
                .input_data = txn.getData().ptr,
                .input_size = txn.getData().len,
                .value = blk: {
                    var txn_value: [32]u8 = undefined;
                    std.mem.writeIntSliceBig(u256, &txn_value, txn.getValue());
                    break :blk .{ .bytes = txn_value };
                },
                .create2_salt = .{
                    .bytes = [_]u8{0} ** 32, // TODO: fix this.
                },
                .code_address = util.to_evmc_address(txn.getTo()), // TODO: fix this when .kind is generalized.
            };
            const result = call(@ptrCast(self), @ptrCast(&msg));

            log.debug("execution result: status_code={}, gas_left={}", .{ result.status_code, result.gas_left });

            remaining_gas = result.gas_left + result.gas_refund;
            // }
        } else { // Contract creation.
            @panic("TODO contract creation");
        }

        const gas_used = @as(i64, @intCast(txn.getGasLimit())) - remaining_gas; // TODO(jsign): decide on casts.

        // Coinbase rewards.
        const gas_tip = 0xa - 0x7; // TODO(jsign): fix, pull from tx_context.
        const coinbase_fee = gas_used * gas_tip;
        try self.statedb.setBalance(self.context.?.block.coinbase, @as(u256, @intCast(coinbase_fee))); // TODO TEMP WRONG

        // Sender fees.
        const sender_fee = gas_used * 0xa;
        try self.statedb.setBalance(from_addr, @as(u256, @intCast(sender_fee))); // TODO TEMP WRONG
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
        return evmc.struct_evmc_tx_context{
            .tx_gas_price = util.to_evmc_bytes32(vm.context.?.txn.gas_price),
            .tx_origin = util.to_evmc_address(vm.context.?.txn.from),
            .block_coinbase = util.to_evmc_address(vm.context.?.block.coinbase),
            .block_number = @intCast(vm.context.?.block.number),
            .block_timestamp = @intCast(vm.context.?.block.timestamp),
            .block_gas_limit = @intCast(vm.context.?.block.gas_limit),
            .block_prev_randao = util.to_evmc_bytes32(vm.context.?.block.prev_randao),
            .chain_id = util.to_evmc_bytes32(vm.context.?.txn.chain_id),
            .block_base_fee = util.to_evmc_bytes32(vm.context.?.block.base_fee),
        };
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
        key: [*c]const evmc.evmc_bytes32,
        value: [*c]const evmc.evmc_bytes32,
    ) callconv(.C) evmc.enum_evmc_storage_status {
        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));

        const skey = std.mem.readIntSlice(u256, &key.*.bytes, std.builtin.Endian.Big);
        const svalue = std.mem.readIntSlice(u256, &value.*.bytes, std.builtin.Endian.Big);

        vm.statedb.setStorage(addr.*.bytes, skey, svalue) catch unreachable; // TODO(jsign): manage catch.

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
        const recipient_account = vm.statedb.getAccount(util.from_evmc_address(msg.*.code_address)) catch unreachable; // TODO(jsign): fix this.
        if (recipient_account.code.len != 0) {
            log.debug("contract call, codelen={d}", .{recipient_account.code.len});
            // Persist the current context. We'll restore it after the call returns.
            const prev_exec_context = vm.*.context.?.execution;

            // Create the new context to be used to do the call.
            vm.context.?.execution = ExecutionContext{ .storage_address = util.from_evmc_address(msg.*.recipient) };

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
            vm.context.?.execution = prev_exec_context;

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