const evmone = @cImport({
    @cInclude("evmone.h");
});
const evmc = @cImport({
    @cInclude("evmc/evmc.h");
});
const std = @import("std");
const util = @import("util.zig");
const types = @import("../types/types.zig");
const Transaction = types.Transaction;
const AccountState = types.AccountState;
const Bytecode = types.Bytecode;
const Address = types.Address;
const log = std.log.scoped(.vm);

pub const StateDB = @import("statedb.zig");

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
    evm: [*c]evmone.evmc_vm,
    // exec_context has the current execution context.
    exec_context: ?ExecutionContext,

    pub fn init(statedb: *StateDB) VM {
        var evm = evmone.evmc_create_evmone();
        log.info("evmone info: name={s}, version={s}, abi_version={d}", .{ evm.*.name, evm.*.version, evm.*.abi_version });
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
        };
    }

    pub fn deinit() void {
        // TODO(jsign): check freeing evmone instance.
    }

    pub fn run_txns(self: *VM, txns: []Transaction) !void {
        // TODO: stashing area.
        for (txns) |txn| {
            self.run_txn(txn);
        }
    }

    fn run_txn(self: *VM, txn: Transaction) void {
        var recipient_code: Bytecode = &[_]u8{};
        if (txn.to) |to| {
            const recipient_account = self.statedb.get(to);
            if (recipient_account) |account| {
                recipient_code = account.code;
            }
        }

        log.debug("running tx", .{}); // TODO(jsign): add txn hash when available.
        const message = evmc.struct_evmc_message{
            .kind = evmc.EVMC_CALL,
            .flags = evmc.EVMC_STATIC,
            .depth = 0,
            // TODO(jsign): why evmc expects a i64 for gas?
            .gas = @intCast(txn.gas_limit),
            .recipient = util.to_evmc_address(txn.to),
            // TODO(jsign): create evmc helper module.
            .sender = util.to_evmc_address(txn.get_from()),
            .input_data = txn.data.ptr,
            .input_size = txn.data.len,
            .value = .{
                .bytes = [_]u8{0} ** 32, // TODO: fix this
            },
            .create2_salt = .{
                .bytes = [_]u8{0} ** 32, // TODO: fix this
            },
            .code_address = util.to_evmc_address(txn.to),
        };

        // Initialize the execution context.
        self.exec_context = ExecutionContext{
            .address = txn.get_from(),
        };

        if (self.evm.*.execute) |exec| {
            // TODO(jsign): EVMC_SHANGHAI should be configurable at runtime.
            var result = exec(self.evm, @ptrCast(&self.host), @ptrCast(self), evmc.EVMC_SHANGHAI, @ptrCast(&message), recipient_code.ptr, recipient_code.len);
            log.debug("execution result: status_code={}, gas_left={}", .{ result.status_code, result.gas_left });
        } else unreachable;
    }

    // ### EVMC Host Interface ###

    fn get_tx_context(ctx: ?*evmc.struct_evmc_host_context) callconv(.C) evmc.struct_evmc_tx_context {
        // tx_gas_price: evmc_uint256be,
        //     tx_origin: evmc_address,
        //     block_coinbase: evmc_address,
        //     block_number: i64,
        //     block_timestamp: i64,
        //     block_gas_limit: i64,
        //     block_prev_randao: evmc_uint256be,
        //     chain_id: evmc_uint256be,
        //     block_base_fee: evmc_uint256be,
        //     blob_hashes: [*c]const evmc_bytes32,
        //     blob_hashes_count: usize,

        _ = ctx;
        @panic("TODO");
    }

    fn get_block_hash(ctx: ?*evmc.struct_evmc_host_context, xx: i64) callconv(.C) evmc.evmc_bytes32 {
        _ = xx;
        _ = ctx;
        @panic("TODO");
    }

    fn account_exists(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) bool {
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn get_storage(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, dest: [*c]const evmc.evmc_bytes32) callconv(.C) evmc.evmc_bytes32 {
        _ = ctx;
        _ = dest;
        _ = addr;
        @panic("TODO");
    }
    fn set_storage(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, value: [*c]const evmc.evmc_bytes32, xxx: [*c]const evmc.evmc_bytes32) callconv(.C) evmc.enum_evmc_storage_status {
        _ = xxx;
        _ = value;
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn get_balance(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) evmc.evmc_uint256be {
        _ = ctx;
        const addr_hex = std.fmt.bytesToHex(addr.*.bytes, std.fmt.Case.lower);
        log.debug("evmc call -> getBalance(0x{s})", .{addr_hex});

        var beval: [32]u8 = undefined;
        std.mem.writeIntSliceBig(u256, &beval, 142);

        return evmc.evmc_uint256be{
            .bytes = beval,
        };
    }

    fn get_code_size(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) usize {
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn get_code_hash(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) evmc.evmc_bytes32 {
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn copy_code(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, xxx: usize, xxy: [*c]u8, xxz: usize) callconv(.C) usize {
        _ = xxz;
        _ = xxy;
        _ = xxx;
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn self_destruct(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, addr2: [*c]const evmc.evmc_address) callconv(.C) bool {
        _ = addr2;
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn emit_log(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, xxx: [*c]const u8, xxy: usize, xxz: [*c]const evmc.evmc_bytes32, xxxzz: usize) callconv(.C) void {
        _ = xxxzz;
        _ = xxz;
        _ = xxy;
        _ = xxx;
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn access_account(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) evmc.enum_evmc_access_status {
        _ = ctx;
        const addr_hex = std.fmt.bytesToHex(addr.*.bytes, std.fmt.Case.lower);
        log.debug("access_account()    accessAccount=0x{s}", .{addr_hex});
        return evmc.EVMC_ACCESS_COLD;
    }

    fn access_storage(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, value: [*c]const evmc.evmc_bytes32) callconv(.C) evmc.enum_evmc_access_status {
        _ = value;
        _ = addr;
        _ = ctx;
        @panic("TODO");
    }

    fn call(ctx: ?*evmc.struct_evmc_host_context, msg: [*c]const evmc.struct_evmc_message) callconv(.C) evmc.struct_evmc_result {
        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        log.debug("call()", .{}); // TODO(jsign): explore creating custom formatter?

        // Persist the current context. We'll restore it after the call return.
        const current_context = vm.*.exec_context.?;
        _ = current_context;

        // Create the new context to be used to do the call.
        vm.exec_context = ExecutionContext{ .address = util.from_evmc_address(msg.*.recipient) };

        var recipient_code: Bytecode = &[_]u8{};
        const recipient_account = vm.statedb.get(util.from_evmc_address(msg.*.code_address));
        if (recipient_account) |account| {
            recipient_code = account.code;
        } else unreachable;

        if (vm.evm.*.execute) |exec| {
            // TODO(jsign): EVMC_SHANGHAI should be configurable at runtime.
            // TODO(jsign): remove ptrCast
            var result = exec(vm.evm, @ptrCast(&vm.host), @ptrCast(vm), evmc.EVMC_SHANGHAI, @ptrCast(msg), recipient_code.ptr, recipient_code.len);
            log.debug("execution result: status_code={}, gas_left={}", .{ result.status_code, result.gas_left });
        } else unreachable;

        @panic("TODO");
    }
};
