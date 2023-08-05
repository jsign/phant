const std = @import("std");
const types = @import("types/types.zig");
const AccountState = types.AccountState;
const Address = types.Address;
const VM = @import("vm/vm.zig").VM;
const StateDB = @import("vm/statedb.zig");
const Transaction = @import("types/types.zig").Transaction;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    std.log.info("Welcome to phant! 🐘", .{});

    // Create some dummy transaction.
    const txn = Transaction{
        .type = 0,
        .chain_id = 1,
        .nonce = 0,
        .gas_price = 10,
        .value = 0,
        .to = [_]u8{0} ** 18 ++ [_]u8{ 0x41, 0x42 },
        .data = &[_]u8{},
        .gas_limit = 10_000,
    };

    // Create the corresponding AccountState for txn.to, in particular with relevant bytecode
    // so the transaction can be properly executed.
    const code = [_]u8{
        0x61, 0x41, 0x42, // PUSH2 0x4142
        0x31, // BALANCE
    };
    var account_state = try AccountState.init(allocator, txn.to.?, 0, 10_000, &code);
    defer account_state.deinit();

    // Create the statedb, with the created account state.
    var account_states = [_]AccountState{account_state};
    var statedb = try StateDB.init(allocator, &account_states);

    // Create the VM with the initialized statedb
    var vm = VM.init(&statedb);

    // Execute transaction.
    vm.run_txns(&[_]Transaction{txn});
}

test "tests" {
    std.testing.log_level = .debug;

    // TODO: at some point unify entrypoint per package.
    // _ = @import("exec-spec-tests/execspectests.zig"); // TODO(jsign): In progress...
    _ = @import("types/types.zig");
    _ = @import("vm/vm.zig");
}
