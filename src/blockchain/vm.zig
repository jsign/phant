const evmc = @cImport({
    @cInclude("evmone.h");
});
const std = @import("std");
const types = @import("../types/types.zig");
const common = @import("../common/common.zig");
const params = @import("params.zig");
const precompiles = @import("precompiles.zig");
const blockchain_types = @import("types.zig");
const Allocator = std.mem.Allocator;
const AddressSet = common.AddressSet;
const AddressKey = common.AddressKey;
const AddressKeySet = common.AddressKeySet;
const Environment = blockchain_types.Environment;
const Message = blockchain_types.Message;
const Block = types.Block;
const Hash32 = types.Hash32;
const Address = types.Address;
const Keccak256 = std.crypto.hash.sha3.Keccak256;
// In Zig 0.15, use {x} format specifier directly on byte slices
const assert = std.debug.assert;

const empty_hash = common.comptimeHexToBytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

pub const VM = struct {
    const vmlog = std.log.scoped(.vm);

    allocator: Allocator,
    env: Environment,
    evm: [*c]evmc.evmc_vm,
    host: evmc.struct_evmc_host_interface,

    // init creates a new EVM VM instance. The caller must call deinit() when done.
    pub fn init(allocator: Allocator, env: Environment) VM {
        const evm = evmc.evmc_create_evmone();
        vmlog.info("evmone info: name={s}, version={s}, abi_version={d}", .{ evm.*.name, evm.*.version, evm.*.abi_version });
        return .{
            .allocator = allocator,
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
                .get_transient_storage = EVMOneHost.get_transient_storage,
                .set_transient_storage = EVMOneHost.set_transient_storage,
            },
        };
    }

    // deinit destroys a VM instance.
    pub fn deinit(self: *VM) void {
        if (self.evm.*.destroy) |destroy| {
            destroy(self.evm);
        }
    }

    // processMessageCall executes a message call.
    pub fn processMessageCall(self: *VM, msg: Message) !MessageCallOutput {
        const evmc_message = if (msg.target) |target| blk: {
            const evmc_message: evmc.struct_evmc_message = .{
                .kind = evmc.EVMC_CALL,
                .flags = 0,
                .depth = 0,
                .gas = @intCast(msg.gas),
                .recipient = toEVMCAddress(target),
                .sender = toEVMCAddress(msg.sender),
                .input_data = msg.data.ptr,
                .input_size = msg.data.len,
                .value = blk2: {
                    var tx_value: [32]u8 = undefined;
                    std.mem.writeInt(u256, &tx_value, msg.value, .big);
                    break :blk2 .{ .bytes = tx_value };
                },
                .create2_salt = undefined, // EVMC docs: field only mandatory for CREATE2 kind which doesn't apply at depth 0.
                .code_address = toEVMCAddress(msg.target),
            };

            try self.env.state.incrementNonce(msg.sender);

            break :blk evmc_message;
        } else blk: {
            break :blk evmc.struct_evmc_message{
                .kind = evmc.EVMC_CREATE,
                .flags = 0,
                .depth = 0,
                .gas = @intCast(msg.gas),
                .recipient = .{
                    .bytes = blk2: {
                        const sender_nonce: u64 = @intCast(self.env.state.getAccount(msg.sender).nonce);
                        break :blk2 common.computeCREATEContractAddress(self.allocator, msg.sender, sender_nonce) catch unreachable;
                    },
                },
                .sender = .{ .bytes = msg.sender },
                .input_data = msg.data.ptr,
                .input_size = msg.data.len,
                .value = blk2: {
                    var tx_value: [32]u8 = undefined;
                    std.mem.writeInt(u256, &tx_value, msg.value, .big);
                    break :blk2 .{ .bytes = tx_value };
                },
                .create2_salt = undefined, // EVMC docs: field only mandatory for CREATE2 kind which doesn't apply at depth 0.
                .code_address = toEVMCAddress(msg.target),
            };
        };

        const result = EVMOneHost.call(@ptrCast(self), @ptrCast(&evmc_message));
        defer {
            if (result.release) |release| release(&result);
        }
        return .{
            .gas_left = @intCast(result.gas_left),
            .refund_counter = @intCast(result.gas_refund),
            .success = result.status_code == evmc.EVMC_SUCCESS,
            .logs = if (result.status_code == evmc.EVMC_SUCCESS)
                (if (self.env.logs) |l| l.items[0..l.items.len] else &[_]types.Log{})
            else
                &[_]types.Log{},
        };
    }
};

// EVMOneHost contains the implementation of the EVMC host interface.
// https://evmc.ethereum.org/structevmc__host__interface.html
const EVMOneHost = struct {
    const evmclog = std.log.scoped(.evmone);

    fn get_tx_context(ctx: ?*evmc.struct_evmc_host_context) callconv(.c) evmc.struct_evmc_tx_context {
        evmclog.debug("getTxContext", .{});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        return evmc.struct_evmc_tx_context{
            .tx_gas_price = toEVMCUint256Be(vm.env.gas_price),
            .tx_origin = toEVMCAddress(vm.env.origin),
            .block_coinbase = toEVMCAddress(vm.env.coinbase),
            .block_number = @intCast(vm.env.number),
            .block_timestamp = @intCast(vm.env.time),
            .block_gas_limit = @intCast(vm.env.gas_limit),
            .block_prev_randao = .{ .bytes = vm.env.prev_randao },
            .chain_id = toEVMCUint256Be(@intFromEnum(vm.env.chain_id)),
            .block_base_fee = toEVMCUint256Be(vm.env.base_fee_per_gas),
            .blob_base_fee = toEVMCUint256Be(vm.env.blob_base_fee),
            .blob_hashes = @ptrCast(vm.env.blob_hashes.ptr),
            .blob_hashes_count = vm.env.blob_hashes.len,
            .initcodes = null,
            .initcodes_count = 0,
        };
    }

    fn get_block_hash(ctx: ?*evmc.struct_evmc_host_context, block_number: i64) callconv(.c) evmc.evmc_bytes32 {
        evmclog.debug("getBlockHash block_number={}", .{block_number});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const idx = @as(u64, @intCast(block_number));
        return .{ .bytes = vm.env.fork.get_parent_block_hash(idx) catch @panic("unhandled error getting parent hash") };
    }

    fn account_exists(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.c) bool {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("accountExists addr=0x{x}", .{&address});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));

        return vm.env.state.getAccountOpt(address) != null;
    }

    fn get_storage(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        key: [*c]const evmc.evmc_bytes32,
    ) callconv(.c) evmc.evmc_bytes32 {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("getStorage addr=0x{x} key={x}", .{ &address, &key.*.bytes });

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const k = std.mem.readInt(u256, &key.*.bytes, std.builtin.Endian.big);

        return .{ .bytes = vm.env.state.getStorage(address, k) };
    }

    fn set_storage(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        key: [*c]const evmc.evmc_bytes32,
        value: [*c]const evmc.evmc_bytes32,
    ) callconv(.c) evmc.enum_evmc_storage_status {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("setStorage addr=0x{x} key={x} value={x}", .{ &address, &key.*.bytes, &value.*.bytes });

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));

        const k = std.mem.readInt(u256, &key.*.bytes, std.builtin.Endian.big);
        const storage_status: evmc.enum_evmc_storage_status = blk: {
            const original_value = vm.env.state.getOriginalStorage(address, k);
            const current_value = vm.env.state.getStorage(address, k);
            const new_value = value.*.bytes;
            const zero = std.mem.zeroes([32]u8);

            // See: https://evmc.ethereum.org/group__EVMC.html#gae012fd6b8e5c23806b507c2d3e9fb1aa

            // EIP-220: 2.
            if (std.mem.eql(u8, &current_value, &new_value)) {
                break :blk evmc.EVMC_STORAGE_ASSIGNED;
            }
            // EIP-220: 3.

            // EIP-220: 3.1
            if (std.mem.eql(u8, &original_value, &current_value)) {
                // EIP-220: 3.1.1
                if (std.mem.eql(u8, &original_value, &zero)) {
                    // 0->0->Z
                    break :blk evmc.EVMC_STORAGE_ADDED;
                }
                if (std.mem.eql(u8, &new_value, &zero)) {
                    // X->X->0
                    break :blk evmc.EVMC_STORAGE_DELETED;
                }
                // X->X->Z
                break :blk evmc.EVMC_STORAGE_MODIFIED;
            }

            // EIP-220: 3.2
            // X != Y

            // EIP-220: 3.2.1
            if (!std.mem.eql(u8, &original_value, &zero)) {
                // EIP-220: 3.2.1.1
                if (std.mem.eql(u8, &current_value, &zero)) {
                    // X->0->Z
                    break :blk evmc.EVMC_STORAGE_DELETED_ADDED;
                }
                // EIP-220: 3.2.1.2
                if (std.mem.eql(u8, &new_value, &zero)) {
                    // X->Y->0
                    break :blk evmc.EVMC_STORAGE_MODIFIED_DELETED;
                }
            }

            // EIP-220: 3.2.2
            if (std.mem.eql(u8, &original_value, &new_value)) {
                if (std.mem.eql(u8, &current_value, &zero)) {
                    // X->0->X
                    break :blk evmc.EVMC_STORAGE_DELETED_RESTORED;
                }
                // EIP-220: 3.2.2.1
                if (std.mem.eql(u8, &original_value, &zero)) {
                    // 0->Y->0
                    break :blk evmc.EVMC_STORAGE_ADDED_DELETED;
                }
                // X->Y->X
                break :blk evmc.EVMC_STORAGE_MODIFIED_RESTORED;
            }

            break :blk evmc.EVMC_STORAGE_ASSIGNED;
        };

        vm.env.state.setStorage(address, k, value.*.bytes) catch |err| switch (err) {
            error.OutOfMemory => @panic("OOO"),
        };


        return storage_status;
    }

    fn get_balance(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.c) evmc.evmc_uint256be {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("getBalance addr=0x{x})", .{&address});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));

        return toEVMCUint256Be(vm.env.state.getAccount(address).balance);
    }

    fn get_code_size(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.c) usize {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("getCodeSize addr=0x{x})", .{&address});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));

        return vm.env.state.getAccount(address).code.len;
    }

    fn get_code_hash(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
    ) callconv(.c) evmc.evmc_bytes32 {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("getCodeHash addr=0x{x})", .{&address});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));

        // EIP-1052: non-existent accounts return 0
        const account = vm.env.state.getAccountOpt(address) orelse return .{ .bytes = std.mem.zeroes([32]u8) };

        var ret = empty_hash;
        if (account.code.len > 0)
            Keccak256.hash(account.code, &ret, .{});

        return .{ .bytes = ret };
    }

    fn copy_code(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        code_offset: usize,
        buffer_data: [*c]u8,
        buffer_size: usize,
    ) callconv(.c) usize {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("copyCode addr=0x{x} code_offset={})", .{ &address, code_offset });

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const code = vm.env.state.getAccount(address).code;

        // Check bounds to prevent integer overflow
        if (code_offset >= code.len) {
            return 0;
        }

        const copy_len = @min(buffer_size, code.len - code_offset);
        @memcpy(buffer_data[0..copy_len], code[code_offset..][0..copy_len]);

        return copy_len;
    }

    fn self_destruct(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        addr2: [*c]const evmc.evmc_address,
    ) callconv(.c) bool {
        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const address = fromEVMCAddress(addr.*);
        const beneficiary = fromEVMCAddress(addr2.*);

        // Transfer balance to beneficiary (add then subtract, handles self-destruct-to-self correctly)
        const balance = vm.env.state.getAccount(address).balance;
        if (balance > 0) {
            const ben_balance = vm.env.state.getAccount(beneficiary).balance;
            vm.env.state.setBalance(beneficiary, ben_balance + balance) catch @panic("OOM in selfdestruct");
            // Re-read balance in case beneficiary == address (it would have changed)
            const addr_balance_now = vm.env.state.getAccount(address).balance;
            vm.env.state.setBalance(address, addr_balance_now - balance) catch @panic("OOM in selfdestruct");
        }

        // EIP-6780 (Cancun): only actually destroy if created in same tx
        const created_in_tx = vm.env.state.wasCreatedInTx(address);
        if (created_in_tx) {
            vm.env.state.markSelfDestructed(address) catch @panic("OOM in selfdestruct");
        }

        vm.env.state.addTouchedAddress(address) catch @panic("OOM in selfdestruct");
        vm.env.state.addTouchedAddress(beneficiary) catch @panic("OOM in selfdestruct");

        return created_in_tx;
    }

    fn emit_log(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        data: [*c]const u8,
        data_size: usize,
        topics: [*c]const evmc.evmc_bytes32,
        topics_count: usize,
    ) callconv(.c) void {
        const vm_inst: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        if (vm_inst.env.logs) |logs| {
            const log_topics = vm_inst.allocator.alloc(types.Hash32, topics_count) catch @panic("OOM in emit_log");
            for (0..topics_count) |i| {
                log_topics[i] = topics[i].bytes;
            }
            const log_data = if (data_size > 0)
                (vm_inst.allocator.dupe(u8, data[0..data_size]) catch @panic("OOM in emit_log"))
            else
                @as([]u8, &[_]u8{});
            logs.append(.{
                .address = fromEVMCAddress(addr.*),
                .topics = log_topics,
                .data = log_data,
            }) catch @panic("OOM in emit_log");
        }
    }

    fn access_account(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.c) evmc.enum_evmc_access_status {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("accessAccount addr=0x{x}", .{&address});

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        if (vm.env.state.accessedAccountsContains(address))
            return evmc.EVMC_ACCESS_WARM;
        vm.env.state.putAccessedAccount(address) catch |err| switch (err) {
            error.OutOfMemory => @panic("OOO"),
        };

        return evmc.EVMC_ACCESS_COLD;
    }

    fn access_storage(
        ctx: ?*evmc.struct_evmc_host_context,
        addr: [*c]const evmc.evmc_address,
        key: [*c]const evmc.evmc_bytes32,
    ) callconv(.c) evmc.enum_evmc_access_status {
        const address = fromEVMCAddress(addr.*);
        evmclog.debug("accessStorage addr=0x{x} key=0x{x}", .{ &address, &key.*.bytes });

        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const address_key: AddressKey = .{ .address = address, .key = key.*.bytes };
        if (vm.env.state.accessedStorageKeysContains(address_key))
            return evmc.EVMC_ACCESS_WARM;
        _ = vm.env.state.putAccessedStorageKeys(address_key) catch |err| switch (err) {
            error.OutOfMemory => @panic("OOO"),
        };

        return evmc.EVMC_ACCESS_COLD;
    }

    fn get_transient_storage(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, key: [*c]const evmc.evmc_bytes32) callconv(.c) evmc.evmc_bytes32 {
        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        const value = vm.env.state.getTransientStorage(fromEVMCAddress(addr.*), key.*.bytes);
        return .{ .bytes = value };
    }

    fn set_transient_storage(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, key: [*c]const evmc.evmc_bytes32, value: [*c]const evmc.evmc_bytes32) callconv(.c) void {
        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));
        vm.env.state.setTransientStorage(fromEVMCAddress(addr.*), key.*.bytes, value.*.bytes) catch @panic("OOM setTransientStorage");
    }

    fn call(ctx: ?*evmc.struct_evmc_host_context, _msg: [*c]const evmc.struct_evmc_message) callconv(.c) evmc.struct_evmc_result {
        const vm: *VM = @as(*VM, @alignCast(@ptrCast(ctx.?)));

        var msg = _msg.*;

        const code = switch (msg.kind) {
            evmc.EVMC_CALL,
            evmc.EVMC_DELEGATECALL,
            evmc.EVMC_CALLCODE,
            => vm.env.state.getAccount(fromEVMCAddress(msg.code_address)).code,
            evmc.EVMC_CREATE,
            evmc.EVMC_CREATE2,
            => if (msg.input_size == 0) &[_]u8{} else msg.input_data[0..msg.input_size],
            else => @panic("unknown message kind"),
        };

        const sender = fromEVMCAddress(msg.sender);
        const recipient = fromEVMCAddress(msg.recipient);

        msg.recipient = switch (msg.kind) {
            evmc.EVMC_CREATE => blk: {
                const sender_nonce: u64 = @intCast(vm.env.state.getAccount(sender).nonce);
                break :blk .{ .bytes = common.computeCREATEContractAddress(vm.allocator, sender, sender_nonce) catch unreachable };
            },
            evmc.EVMC_CREATE2 => .{ .bytes = common.computeCREATE2ContractAddress(sender, msg.create2_salt.bytes, code) catch unreachable },
            evmc.EVMC_CALL,
            evmc.EVMC_DELEGATECALL,
            evmc.EVMC_CALLCODE,
            => msg.recipient,
            else => @panic("unknown message kind"),
        };

        evmclog.debug("call() kind={d} depth={d} sender={x} recipient={x} gas={}", .{ msg.kind, msg.depth, &msg.sender.bytes, &msg.recipient.bytes, msg.gas });

        if (msg.depth > params.stack_depth_limit) {
            return .{
                .status_code = evmc.EVMC_CALL_DEPTH_EXCEEDED,
                .gas_left = 0,
                .gas_refund = 0,
                .output_data = null,
                .output_size = 0,
                .release = null,
                .create_address = std.mem.zeroes(evmc.struct_evmc_address),
                .padding = [_]u8{0} ** 4,
            };
        }

        vm.env.state.putAccessedAccount(recipient) catch |err| switch (err) {
            error.OutOfMemory => @panic("OOO"),
        };

        if (msg.kind == evmc.EVMC_CREATE or msg.kind == evmc.EVMC_CREATE2) {
            // Increment the nonce of the contract creator.
            vm.env.state.incrementNonce(sender) catch unreachable;
            // Ensure the new contract account exists in StateDB before executing code.
            if (vm.env.state.getAccountOpt(recipient) == null) {
                vm.env.state.setBalance(recipient, 0) catch |err| switch (err) {
                    error.OutOfMemory => @panic("OOO"),
                };
            }
            // EIP-6780: track accounts created in this tx
            vm.env.state.markCreated(recipient) catch @panic("OOM markCreated");
        }

        // Persist current context in case we need it for scope revert.
        var prev_statedb = vm.env.state.snapshot() catch |err| switch (err) {
            error.OutOfMemory => @panic("OOO"),
        };

        // Send value (not for CALLCODE/DELEGATECALL — they execute in the caller's context).
        const value = std.mem.readInt(u256, &msg.value.bytes, std.builtin.Endian.big);
        if (value > 0 and msg.kind != evmc.EVMC_CALLCODE and msg.kind != evmc.EVMC_DELEGATECALL) {
            const sender_balance = vm.env.state.getAccount(sender).balance;
            if (sender_balance < value) {
                return .{
                    .status_code = evmc.EVMC_INSUFFICIENT_BALANCE,
                    .gas_left = 0,
                    .gas_refund = 0,
                    .output_data = null,
                    .output_size = 0,
                    .release = null,
                    .create_address = std.mem.zeroes(evmc.struct_evmc_address),
                    .padding = [_]u8{0} ** 4,
                };
            }
            vm.env.state.setBalance(sender, sender_balance - value) catch |err| switch (err) {
                error.OutOfMemory => @panic("OOO"),
            };
            const recipient_balance = vm.env.state.getAccount(recipient).balance;
            vm.env.state.setBalance(recipient, recipient_balance + value) catch |err| switch (err) {
                error.OutOfMemory => @panic("OOO"),
            };
        }

        // Check if the target is a precompile — execute natively instead of via EVM.
        const precompile_result = precompiles.execute(fromEVMCAddress(msg.code_address), if (msg.input_size > 0) msg.input_data[0..msg.input_size] else &[_]u8{}, msg.gas, vm.env.evmc_revision);

        var result = if (precompile_result) |pr| evmc.struct_evmc_result{
            .status_code = @intCast(pr.status_code),
            .gas_left = pr.gas_left,
            .gas_refund = pr.gas_refund,
            .output_data = pr.output_data,
            .output_size = pr.output_size,
            .release = null,
            .create_address = std.mem.zeroes(evmc.struct_evmc_address),
            .padding = [_]u8{0} ** 4,
        } else vm.evm.*.execute.?(
            vm.evm,
            @ptrCast(&vm.host),
            @ptrCast(vm),
            @intCast(vm.env.evmc_revision),
            &msg,
            code.ptr,
            code.len,
        );

        if (result.status_code == evmc.EVMC_SUCCESS) {
            if (msg.kind == evmc.EVMC_CREATE or msg.kind == evmc.EVMC_CREATE2) {
                const contract_code_gas = @as(i64, @intCast(result.output_size)) * params.gas_code_deposit;

                if ((result.output_size > 0 and result.output_data == 0xEF) or result.output_size > params.max_code_size or contract_code_gas > result.gas_left) {
                    result.release.?(&result);
                    vm.env.state.* = prev_statedb;
                    return .{
                        .status_code = evmc.EVMC_FAILURE,
                        .gas_left = 0,
                        .gas_refund = 0,
                        .output_data = null,
                        .output_size = 0,
                        .release = null,
                        .create_address = std.mem.zeroes(evmc.struct_evmc_address),
                        .padding = [_]u8{0} ** 4,
                    };
                }
                result.gas_left -= contract_code_gas;
                result.create_address = msg.recipient;

                // Save new contract code and set nonce to 1.
                const contract_code = if (result.output_size == 0) &[_]u8{} else result.output_data[0..result.output_size];
                vm.env.state.setContractCode(fromEVMCAddress(msg.recipient), contract_code) catch |err| switch (err) {
                    error.OutOfMemory => @panic("OOO"),
                    error.AccountAlreadyHasCode => @panic("account already has code"),
                };
                vm.env.state.incrementNonce(fromEVMCAddress(msg.recipient)) catch unreachable;
            }
            // Free the backup and indirectly commit to the changes that happened.
            prev_statedb.deinit();

            // EIP-158.
            if (vm.env.state.isEmpty(recipient))
                vm.env.state.addTouchedAddress(recipient) catch |err| switch (err) {
                    error.OutOfMemory => @panic("OOO"),
                };
        } else {
            // If the *CALL failed, we restore the previous statedb.
            // EIP-2929: accessed accounts/storage persist across reverts.
            const current_accessed_accounts = vm.env.state.accessed_accounts;
            const current_accessed_storage = vm.env.state.accessed_storage_keys;
            prev_statedb.accessed_accounts.deinit();
            prev_statedb.accessed_storage_keys.deinit();
            prev_statedb.accessed_accounts = current_accessed_accounts;
            prev_statedb.accessed_storage_keys = current_accessed_storage;
            vm.env.state.* = prev_statedb;
        }
        evmclog.debug("call() end depth={d} status_code={} gas_left={} gas_refund={} create_address={x}", .{ msg.depth, result.status_code, result.gas_left, result.gas_refund, &result.create_address.bytes });

        return result;
    }
};

// toEVMCAddress transforms an Address or ?Address into an evmc_address.
fn toEVMCAddress(address: anytype) evmc.struct_evmc_address {
    const addr_typeinfo = @typeInfo(@TypeOf(address));
    if (@TypeOf(address) != Address and addr_typeinfo.optional.child != Address) {
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

fn toEVMCUint256Be(num: u256) evmc.evmc_uint256be {
    return .{
        .bytes = blk: {
            var ret: [32]u8 = undefined;
            std.mem.writeInt(u256, &ret, num, std.builtin.Endian.big);
            break :blk ret;
        },
    };
}

pub const MessageCallOutput = struct {
    success: bool,
    gas_left: u64,
    refund_counter: u64,
    logs: []const types.Log = &[_]types.Log{},
};
