// TODO(pre-review): check usage of all imports.
const evmc = @cImport({
    @cInclude("evmone.h");
});
const std = @import("std");
const types = @import("../types/types.zig");
const common = @import("../common/common.zig");
const blockchain = @import("blockchain.zig").Blockchain; // TODO: unnest
const Allocator = std.mem.Allocator;
const AddressSet = common.AddressSet;
const AddressKey = common.AddressKey;
const AddressKeySet = common.AddressKeySet;
const Environment = blockchain.Environment;
const Message = blockchain.Message;
const Txn = types.Txn;
const TxnSigner = @import("../signer/signer.zig").TxnSigner;
const Block = types.Block;
const AccountState = types.AccountState;
const Bytecode = types.Bytecode;
const Hash32 = types.Hash32;
const Address = types.Address;
const StateDB = @import("../statedb/statedb.zig");
const Keccak256 = std.crypto.hash.sha3.Keccak256;
const fmtSliceHexLower = std.fmt.fmtSliceHexLower;
const assert = std.debug.assert;

const STACK_DEPTH_LIMIT = 1024;
const empty_hash = common.comptimeHexToBytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

pub const VM = struct {
    env: Environment,
    evm: [*c]evmc.evmc_vm,
    host: evmc.struct_evmc_host_interface,

    // Call context scoped variables.
    accessed_accounts: AddressSet,
    accessed_storage_keys: AddressKeySet,

    const vmlog = std.log.scoped(.vm);

    // init creates a new EVM VM instance. The caller must call deinit() when done.
    pub fn init(env: Environment) VM {
        var evm = evmc.evmc_create_evmone();
        vmlog.info("evmone info: name={s}, version={s}, abi_version={d}", .{ evm.*.name, evm.*.version, evm.*.abi_version });
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
            // TODO: remove this and move it to a "VM instance" or similar which has a
            // context containing these things, and probably also the (snapshoted) statedb.
            .accessed_accounts = undefined,
            .accessed_storage_keys = undefined,
        };
    }

    // deinit destroys a VM instance.
    pub fn deinit(self: *VM) void {
        self.evm.destroy();
        self.evm = undefined;
    }

    // processMessageCall executes a message call.
    pub fn processMessageCall(self: *VM, allocator: Allocator, msg: Message) !evmc.struct_evmc_result {
        const evmc_message: evmc.struct_evmc_message = .{
            .kind = if (msg.target != null) evmc.EVMC_CALL else evmc.EVMC_CREATE,
            .flags = 0,
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

        // TODO(improv): we clone here since it's the easiest way to manage ownership of the sets.
        // Quite honestly, it will be better to avoid creating the sets at the caller level and do it here
        // which would make the ownership problem disappear and avoid the clone. It's a very cheap
        // clone, but also is simple to avoid it.
        self.accessed_accounts = try msg.accessed_addresses.cloneWithAllocator(allocator);
        defer self.accessed_accounts.deinit();
        self.accessed_storage_keys = try msg.accessed_storage_keys.cloneWithAllocator(allocator);
        defer self.accessed_storage_keys.deinit();

        const result = EVMOneHost.call(@ptrCast(self), @ptrCast(&evmc_message));
        vmlog.debug("processMessageCall status_code={}, gas_left={}", .{ result.status_code, result.gas_left });
        return result;
    }
};

// EVMOneHost contains the implementation of the EVMC host interface.
// https://evmc.ethereum.org/structevmc__host__interface.html
const EVMOneHost = struct {
    const evmclog = std.log.scoped(.evmone);

    fn get_tx_context(ctx: ?*evmc.struct_evmc_host_context) callconv(.C) evmc.struct_evmc_tx_context {
        evmclog.debug("get_tx_context", .{});

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
        evmclog.debug("get_tx_context block_number={}", .{block_number});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const idx = vm.env.number - block_number;
        if (idx < 0 or idx >= vm.env.block_hashes.len) {
            return std.mem.zeroes(evmc.evmc_bytes32);
        }
        return .{ .bytes = vm.env.block_hashes[idx] };
    }

    fn account_exists(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) bool {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("account_exists addr=0x{}", .{fmtSliceHexLower(&address)});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        return try vm.env.state.getAccount() != null;
    }

    fn get_storage(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        key: [*c]const evmc.evmc_bytes32,
    ) callconv(.C) evmc.evmc_bytes32 {
        evmclog.debug("get_storage addr=0x{} key={}", .{ fmtSliceHexLower(&addr), fmtSliceHexLower(&key.*) });

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const k = std.mem.readIntSlice(u256, &key.*.bytes, std.builtin.Endian.Big);
        const address = fromEVMCAddress(addr.*);
        return vm.env.state.getStorage(address, k) orelse std.mem.zeroes(Hash32);
    }

    fn set_storage(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        key: [*c]const evmc.evmc_bytes32,
        value: [*c]const evmc.evmc_bytes32,
    ) callconv(.C) evmc.enum_evmc_storage_status {
        evmclog.debug("set_storage addr=0x{} key={} value={}", .{ fmtSliceHexLower(&addr), fmtSliceHexLower(&key.*), fmtSliceHexLower(&value.*) });

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const address = fromEVMCAddress(addr.*);
        const k = std.mem.readIntSlice(u256, &key.*.bytes, std.builtin.Endian.Big);
        const v = std.mem.readIntSlice(u256, &value.*.bytes, std.builtin.Endian.Big);
        vm.env.state.setStorage(address, k, v) catch |err| switch (err) {
            // From EVMC docs: "The VM MUST make sure that the account exists. This requirement is only a formality
            // because VM implementations only modify storage of the account of the current execution context".
            error.AccountDoesNotExist => @panic("set storage in non-existent account"),
            else => @panic("OOO"),
        };
        return evmc.EVMC_STORAGE_ADDED; // TODO(jsign): fix https://evmc.ethereum.org/group__EVMC.html#gae012fd6b8e5c23806b507c2d3e9fb1aa
    }

    fn get_balance(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) evmc.evmc_uint256be {
        evmclog.debug("getBalance addr=0x{})", .{fmtSliceHexLower(&addr)});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const address = fromEVMCAddress(addr.*);
        const balance_bytes = blk: {
            const balance = vm.env.state.getAccount(address) orelse 0;
            var buf: [32]u8 = undefined;
            std.mem.writeIntSliceBig(u256, &buf, balance);
            break :blk buf;
        };
        return evmc.evmc_uint256be{ .bytes = balance_bytes };
    }

    fn get_code_size(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) usize {
        evmclog.debug("getCodeSize addr=0x{})", .{fmtSliceHexLower(&addr)});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const address = fromEVMCAddress(addr.*);
        return if (vm.env.state.getCode(address)) |code| code.len else 0;
    }

    fn get_code_hash(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
    ) callconv(.C) evmc.evmc_bytes32 {
        evmclog.debug("getCodeSize addr=0x{})", .{fmtSliceHexLower(&addr)});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const address = fromEVMCAddress(addr.*);
        const ret = empty_hash;
        if (vm.env.state.getCode(address)) |code| {
            Keccak256.hash(&ret, code, .{});
        }
        return ret;
    }

    fn copy_code(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        code_offset: usize,
        buffer_data: [*c]u8,
        buffer_size: usize,
    ) callconv(.C) usize {
        evmclog.debug("copyCode addr=0x{} code_offset={})", .{ fmtSliceHexLower(&addr), code_offset });

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const address = fromEVMCAddress(addr.*);
        const code = vm.env.state.getCode(address) orelse @panic("copyCode account doesn't exist");

        const copy_len = @min(buffer_size, code.len - code_offset);
        @memcpy(buffer_data, code[code_offset..][0..copy_len]);
    }

    fn self_destruct(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        addr2: [*c]const evmc.evmc_address,
    ) callconv(.C) bool {
        _ = addr2;
        _ = addr;
        _ = ctx;
        // https://evmc.ethereum.org/group__EVMC.html#ga1aa9fa657b3f0de375e2f07e53b65bcc
        @panic("self destruct not supported in verkle");
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
        // https://evmc.ethereum.org/group__EVMC.html#gaab96621b67d653758b3da15c2b596938
        @panic("TODO");
    }

    fn access_account(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) evmc.enum_evmc_access_status {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("accessAccount addr=0x{}", .{fmtSliceHexLower(&address)});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        if (vm.accessed_accounts.contains(address))
            return evmc.EVMC_ACCESS_WARM;
        _ = vm.accessed_accounts.fetchPut(address, {}) catch @panic("OOO");

        return evmc.EVMC_ACCESS_COLD;
    }

    fn access_storage(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        key: [*c]const evmc.evmc_bytes32,
    ) callconv(.C) evmc.enum_evmc_access_status {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("accessStorage addr=0x{} key=0x{}", .{ fmtSliceHexLower(&address), fmtSliceHexLower(&key.*.bytes) });

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const address_key: AddressKey = .{ .address = address, .key = key.*.bytes };
        if (vm.accessed_storage_keys.contains(address_key))
            return evmc.EVMC_ACCESS_WARM;
        _ = vm.accessed_storage_keys.fetchPut(address_key, {}) catch @panic("OOO");

        return evmc.EVMC_ACCESS_COLD;
    }

    fn call(ctx: ?*evmc.struct_evmc_host_context, msg: [*c]const evmc.struct_evmc_message) callconv(.C) evmc.struct_evmc_result {
        evmclog.debug("call() kind={d} depth={d} sender={} recipient={}", .{ msg.kind, msg.*.depth, fmtSliceHexLower(&msg.*.sender.bytes), fmtSliceHexLower(&msg.*.recipient.bytes) }); // TODO(jsign): explore creating custom formatter?

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));

        if (msg.depth > STACK_DEPTH_LIMIT) {
            return .{
                .status_code = evmc.EVMC_CALL_DEPTH_EXCEEDED,
                .gas_left = 0,
                .gas_refund = 0,
                .output_data = null,
                .output_size = 0,
                .release = null,
                .create_address = std.mem.zeroes(evmc.struct_evmc_address),
                .padding = [_]u9{0} ** 4,
            };
        }

        // Save current context.
        const prev_accessed_accounts = vm.accessed_accounts;
        const prev_accessed_storage_keys = vm.accessed_storage_keys;
        const prev_statedb = vm.env.state;

        // Create new call context.
        vm.accessed_accounts = vm.accessed_accounts.clone();
        defer vm.accessed_accounts.deinit();
        vm.accessed_storage_keys = vm.accessed_storage_keys.clone();
        defer vm.accessed_storage_keys.deinit();
        vm.env.state = vm.env.state.snapshot();
        defer vm.env.state.deinit();

        // Send value.
        if (msg.value.bytes != [_]u8{0} ** 32) {
            const value = std.mem.readInt(u256, &msg.*.value.bytes, std.builtin.Endian.Big);

            const sender = toEVMCAddress(msg.sender);
            const sender_balance = if (vm.env.state.getAccount(sender)) |acc| acc.balance else 0;
            if (sender_balance < value) {
                return .{
                    .status_code = evmc.EVMC_INSUFFICIENT_BALANCE,
                    .gas_left = 0,
                    .gas_refund = 0,
                    .output_data = null,
                    .output_size = 0,
                    .release = null,
                    .create_address = std.mem.zeroes(evmc.struct_evmc_address),
                    .padding = [_]u9{0} ** 4,
                };
            }
            vm.env.state.setBalance(sender, sender_balance - value) catch @panic("OOO");
            const receipient_balance = if (vm.env.state.getAccount(toEVMCAddress(msg.recipient))) |acc| acc.balance else 0;
            vm.env.state.setBalance(sender, receipient_balance + value) catch @panic("OOO");
        }
        const value = std.mem.readInt(u256, &msg.*.value.bytes, std.builtin.Endian.Big);
        _ = value;

        const code_address = toEVMCAddress(msg.code_address);
        const code = vm.env.state.getCode(code_address);
        var result = vm.evm.*.execute.?(
            vm.evm,
            @ptrCast(&vm.host),
            @ptrCast(vm),
            evmc.EVMC_SHANGHAI, // TODO: generalize from block_number.
            msg,
            code.code.ptr,
            code.code.len,
        );
        evmclog.debug("internal call exec result: status_code={}, gas_left={}", .{ result.status_code, result.gas_left });

        if (result.status_code != evmc.EVMC_SUCCESS) {
            // Restore previous context.
            vm.accessed_accounts = prev_accessed_accounts;
            vm.accessed_storage_keys = prev_accessed_storage_keys;
            vm.env.state = prev_statedb;
        }

        return result;
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
