const evmc = @cImport({
    @cInclude("evmone.h");
});
const std = @import("std");
const types = @import("../types/types.zig");
const blockchain = @import("blockchain.zig").Blockchain; // TODO: unnest
const Allocator = std.mem.Allocator;
const Environment = blockchain.Environment;
const Message = blockchain.Message;
const Txn = types.Txn;
const TxnSigner = @import("../signer/signer.zig").TxnSigner;
const Block = types.Block;
const AccountState = types.AccountState;
const Bytecode = types.Bytecode;
const Address = types.Address;
const StateDB = @import("../vm/statedb.zig");
const fmtSliceHexLower = std.fmt.fmtSliceHexLower;
const assert = std.debug.assert;

const log = std.log.scoped(.vm);

pub const VM = struct {
    env: Environment,
    evm: [*c]evmc.evmc_vm,
    host: evmc.struct_evmc_host_interface,

    // init creates a new EVM VM instance. The caller must call deinit() when done.
    pub fn init(env: Environment) VM {
        var evm = evmc.evmc_create_evmone();
        log.info("evmone info: name={s}, version={s}, abi_version={d}", .{ evm.*.name, evm.*.version, evm.*.abi_version });
        return .{
            .env = env,
            .evm = evm,
            .host = evmc.struct_evmc_host_interface{
                .account_exists = EVMOneHost.account_exists,
                .get_storage = EVMOneHost.get_storage,
                .set_storage = EVMOneHost.set_storage,
                .get_balance = EVMOneHost.get_balance,
                .get_code_size = EVMOneHost.get_code_size,
                .get_code_hash = EVMOneHost.get_code_hash,
                .copy_code = EVMOneHost.copy_code,
                .selfdestruct = EVMOneHost.self_destruct,
                .call = EVMOneHost.call,
                .get_tx_context = EVMOneHost.get_tx_context,
                .get_block_hash = EVMOneHost.get_block_hash,
                .emit_log = EVMOneHost.emit_log,
                .access_account = EVMOneHost.access_account,
                .access_storage = EVMOneHost.access_storage,
            },
        };
    }

    // deinit destroys a VM instance.
    pub fn deinit(self: *VM) void {
        self.evm.destroy();
        self.evm = undefined;
    }

    pub fn processMessageCall(self: *VM, msg: Message) !evmc.struct_evmc_result {
        const kind = if (msg.target) evmc.EVMC_CALL orelse evmc.EVMC_CREATE;
        const evmc_message = evmc.struct_evmc_message{
            .kind = kind,
            .flags = evmc.EVMC_STATIC,
            .depth = 0,
            .gas = @intCast(msg.gas),
            .recipient = toEVMCAddress(msg.current_target),
            .sender = toEVMCAddress(msg.caller),
            .input_data = msg.data.ptr,
            .input_size = msg.data.len,
            .value = blk: {
                var txn_value: [32]u8 = undefined;
                std.mem.writeIntSliceBig(u256, &txn_value, msg.value);
                break :blk .{ .bytes = txn_value };
            },
            .create2_salt = undefined, // EVMC docs: field only mandatory for CREATE2 kind.
            .code_address = undefined, // EVMC docs: field not mandatory for depth 0 calls.
        };
        const result = EVMOneHost.call(@ptrCast(self), @ptrCast(&evmc_message));
        log.debug("execution result: status_code={}, gas_left={}", .{ result.status_code, result.gas_left });
        return result;
    }
};

// EVMOneHost contains the implementation of the EVMC host interface.
// https://evmc.ethereum.org/structevmc__host__interface.html
const EVMOneHost = struct {
    fn get_tx_context(ctx: ?*evmc.struct_evmc_host_context) callconv(.C) evmc.struct_evmc_tx_context {
        log.debug("get_tx_context()", .{});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?))); // TODO: alignCast needed?
        return evmc.struct_evmc_tx_context{
            .tx_gas_price = toEVMCBytes32(vm.env.?.txn.gas_price),
            .tx_origin = toEVMCAddress(vm.env.?.txn.from),
            .block_coinbase = toEVMCAddress(vm.env.?.block.coinbase),
            .block_number = @intCast(vm.env.?.block.number),
            .block_timestamp = @intCast(vm.env.?.block.timestamp),
            .block_gas_limit = @intCast(vm.env.?.block.gas_limit),
            .block_prev_randao = toEVMCBytes32(vm.env.?.block.prev_randao),
            .chain_id = toEVMCBytes32(vm.env.?.txn.chain_id),
            .block_base_fee = toEVMCBytes32(vm.env.?.block.base_fee),
        };
    }

    fn get_block_hash(ctx: ?*evmc.struct_evmc_host_context, block_number: i64) callconv(.C) evmc.evmc_bytes32 {
        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const idx = vm.env.number - block_number;
        if (idx < 0 or idx >= vm.env.block_hashes.len) {
            return .{ .bytes = [_]u8{0} ** 32 };
        }
        return .{ .bytes = vm.env.block_hashes[idx] };
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
        log.debug("access_account(addr={})", .{fmtSliceHexLower(&addr.*.bytes)});
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

    fn call(ctx: ?*evmc.struct_evmc_host_context, msg: [*c]const evmc.struct_evmc_message) callconv(.C) evmc.struct_evmc_result {
        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        log.debug("call depth={d} sender={} recipient={}", .{ msg.*.depth, fmtSliceHexLower(&msg.*.sender.bytes), fmtSliceHexLower(&msg.*.recipient.bytes) }); // TODO(jsign): explore creating custom formatter?

        // Check if the target address is a contract, and do the appropiate call.
        const recipient_account = vm.statedb.getAccount(fromEVMCAddress(msg.*.code_address)) catch unreachable; // TODO(jsign): fix this.
        if (recipient_account.code.len != 0) {
            log.debug("contract call, codelen={d}", .{recipient_account.code.len});
            // Persist the current context. We'll restore it after the call returns.
            const prev_exec_context = vm.*.env.?.env;

            // Create the new context to be used to do the call.
            vm.env.?.env = ExecutionContext{ .storage_address = util.from_evmc_address(msg.*.recipient) };

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
            vm.env.?.env = prev_exec_context;

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

// toEVMCAddress transforms an Address or ?Address into an evmc_address.
fn toEVMCAddress(address: anytype) evmc.struct_evmc_address {
    const addr_typeinfo = @typeInfo(@TypeOf(address));
    if (@TypeOf(address) != Address and addr_typeinfo.Optional.child != Address) {
        @compileError("address must be of type Address or ?Address");
    }

    // Address type.
    if (@TypeOf(address) == Address) {
        return evmc.struct_evmc_address{
            .bytes = address,
        };
    }
    if (address) |addr| {
        return toEVMCAddress(addr);
    }
    return evmc.struct_evmc_address{
        .bytes = [_]u8{0} ** 20,
    };
}

// fromEVMCAddress transforms an evmc_address into an Address.
fn fromEVMCAddress(address: evmc.struct_evmc_address) Address {
    return address.bytes;
}

// toEVMCBytes32 transforms a u256 into an evmc_bytes32.
fn toEVMCBytes32(num: u256) evmc.evmc_bytes32 {
    return evmc.struct_evmc_bytes32{
        .bytes = blk: {
            var ret: [32]u8 = undefined;
            std.mem.writeIntSliceBig(u256, &ret, num);
            break :blk ret;
        },
    };
}
