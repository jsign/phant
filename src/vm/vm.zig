const evmc = @cImport({
    @cInclude("evmone.h");
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
    evm: [*c]evmc.evmc_vm,

    // exec_context has the current execution context.
    exec_context: ?ExecutionContext,
    // tx_context for the current execution.
    tx_context: ?evmc.struct_evmc_tx_context,

    pub fn init(statedb: *StateDB) VM {
        var evm = evmc.evmc_create_evmone();
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
            .tx_context = null,
        };
    }

    pub fn deinit() void {
        // TODO(jsign): check freeing evmone instance.
    }

    pub fn run_txns(self: *VM, txns: []const Transaction) void {
        // TODO: stashing area.
        for (txns) |txn| {
            self.tx_context = evmc.struct_evmc_tx_context{
                .tx_gas_price = util.to_evmc_bytes32(txn.gas_price),
                .tx_origin = util.to_evmc_address(txn.get_from()),
                .block_coinbase = std.mem.zeroes(evmc.struct_evmc_address),
                .block_number = 0, // TODO
                .block_timestamp = 0, // TODO
                .block_gas_limit = 0, // TODO
                .block_prev_randao = std.mem.zeroes(evmc.evmc_uint256be), // TODO
                .chain_id = util.to_evmc_bytes32(txn.chain_id),
                .block_base_fee = std.mem.zeroes(evmc.evmc_uint256be), // TODO
                .blob_hashes = null, // TODO
                .blob_hashes_count = 0, // TODO
            };
            self.run_txn(txn);
        }
    }

    pub fn run_txn(self: *VM, txn: Transaction) void {
        log.debug("running tx", .{}); // TODO(jsign): add txn hash when available.

        var recipient_code: Bytecode = &[_]u8{};
        if (txn.to) |to| {
            if (self.statedb.get(to)) |account| {
                recipient_code = account.code;
            }
        }

        const message = evmc.struct_evmc_message{
            .kind = evmc.EVMC_CALL, // TODO(jsign): generalize.
            .flags = evmc.EVMC_STATIC,
            .depth = 0,
            .gas = @intCast(txn.gas_limit), // TODO(jsign): why evmc expects a i64 for gas instead of u64?
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

        // Initialize the execution context.
        self.exec_context = ExecutionContext{
            .address = txn.get_from(),
        };

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
    }

    // ### EVMC Host Interface ###

    fn get_tx_context(ctx: ?*evmc.struct_evmc_host_context) callconv(.C) evmc.struct_evmc_tx_context {
        log.debug("get_tx_context()", .{});
        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        return vm.tx_context.?;
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
        } else {
            unreachable;
        }

        if (vm.evm.*.execute) |exec| {
            // TODO(jsign): EVMC_SHANGHAI should be configurable at runtime.
            // TODO(jsign): remove ptrCast
            var result = exec(vm.evm, @ptrCast(&vm.host), @ptrCast(vm), evmc.EVMC_SHANGHAI, msg, recipient_code.ptr, recipient_code.len);
            log.debug("execution result: status_code={}, gas_left={}", .{ result.status_code, result.gas_left });
        } else unreachable;

        @panic("TODO");
    }
};
