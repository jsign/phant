const evmone = @cImport({
    @cInclude("evmone.h");
});
const evmc = @cImport({
    @cInclude("evmc/evmc.h");
});
const std = @import("std");
pub const types = @import("types.zig");
const Transaction = types.Transaction;
const AccountState = types.AccountState;
const Bytecode = types.Transaction;
const Address = types.Address;
const StateDb = @import("../statedb/statedb.zig");
const Host = @import("evmchost.zig");
const log = std.log.scoped(.vm);

host: Host,
evm: [*c]evmone.evmc_vm,

pub fn init(statedb: *StateDb) @This() {
    const evm = evmone.evmc_create_evmone();
    var host = Host.init(statedb);
    return @This(){
        .host = host,
        .evm = evm,
    };
}

pub fn run_txns(self: *const @This(), txns: []Transaction) !void {
    // TODO: stashing area.
    for (txns) |txn| {
        self.run_txn(txn);
    }
}

fn run_txn(self: *const @This(), txn: Transaction) void {
    const recipient_code: struct { code: [*c]const u8, size: usize } = blk: {
        if (txn.to == null) {
            break :blk .{ .code = null, .size = 0 };
        }

        const statedb = self.host.statedb;
        const recipient_account: ?AccountState = statedb.get(txn.to.?);
        if (recipient_account == null) {
            break :blk .{ .code = null, .size = 0 };
        }
        break :blk .{ .code = @ptrCast(&recipient_account.?.code), .size = @as(usize, recipient_account.?.code.len) };
    };
    log.debug("running tx", .{}); // TODO(jsign): add txn hash when available.
    const message = evmc.struct_evmc_message{
        .kind = evmc.EVMC_CALL,
        .flags = evmc.EVMC_STATIC,
        .depth = 0,
        // TODO(jsign): why evmc expects a i64 for gas?
        .gas = @intCast(txn.gas_limit),
        .recipient = to_evmc_address(txn.to),
        // TODO(jsign): create evmc helper module.
        .sender = to_evmc_address(txn.get_from()),
        .input_data = txn.data.ptr,
        .input_size = txn.data.len,
        .value = .{
            .bytes = [_]u8{0} ** 32,
        },
        .create2_salt = .{
            .bytes = [_]u8{0} ** 32,
        },
        .code_address = to_evmc_address(txn.to),
    };

    if (self.evm.*.execute) |exec| {
        var result = exec(self.evm, @ptrCast(&self.host.evmc_host), null, evmc.EVMC_SHANGHAI, @ptrCast(&message), recipient_code.code, recipient_code.size);
        log.debug("execution result: status_code={}, gas_left={}", .{ result.status_code, result.gas_left });
    }
}

fn to_evmc_address(address: anytype) evmc.struct_evmc_address {
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
        return to_evmc_address(addr);
    }
    return evmc.struct_evmc_address{
        .bytes = [_]u8{0} ** 20,
    };
}
