const std = @import("std");
const types = @import("types/types.zig");
const AccountState = types.AccountState;
const Address = types.AccountState;
const VM = @import("vm/vm.zig").VM;
const StateDB = @import("vm/statedb.zig");
const Transaction = @import("types/types.zig").Transaction;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    std.log.info("Welcome to phant! 🐘", .{});

    var statedb = try StateDB.init(allocator, &[_]AccountState{});
    const vm = VM.init(&statedb);
    _ = vm;

    const txn = Transaction{
        .type = 0,
        .chain_id = 1,
        .nonce = 0,
        .gas_price = 10,
        .value = 0,
        .to = comptime blk: {
            var addr: Address = undefined;
            _ = std.fmt.hexToBytes(&addr, "4200000000000000000000000000000000000000000000000000000000000041");

            break :blk addr;
        },
        .data = &[_]u8{},
        .gas_limit = 10_000,
    };
    _ = txn;

    const code = [_]u8{
        0x61, 0x41, 0x42, // PUSH2 0x4142
        // 0x31, // BALANCE
    };
    _ = code;

    //     const message = evmc.struct_evmc_message{
    //         .kind = evmc.EVMC_CALL,
    //         .flags = 0,
    //         .depth = 0,
    //         .gas = 10_000,
    //         .recipient = addr2,
    //         .sender = addr,
    //         .input_data = &[_]u8{},
    //         .input_size = 0,
    //         .value = .{
    //             .bytes = [_]u8{0} ** 32,
    //         },
    //         .create2_salt = .{
    //             .bytes = [_]u8{0} ** 32,
    //         },
    //         .code_address = addr2,
    //     };
    //     std.log.info("0x{} bytecode: {} (PUSH2 0x4142; BALANCE;)", .{ std.fmt.fmtSliceHexLower(&message.recipient.bytes), std.fmt.fmtSliceHexLower(&code) });
    //     std.log.info("executing message -> gas={}, sender=0x{}, recipient=0x{}", .{ message.gas, std.fmt.fmtSliceHexLower(&message.sender.bytes), std.fmt.fmtSliceHexLower(&message.recipient.bytes) });

    //    if (vm.*.execute) |exec| {
    //         var result = exec(vm, @ptrCast(&host.evmc_host), null, evmc.EVMC_SHANGHAI, @ptrCast(&message), @ptrCast(&code), code.len);
    //         std.log.info("execution result -> status_code={}, gas_left={}", .{ result.status_code, result.gas_left });
    //     }
}

test "tests" {
    std.testing.log_level = .debug;

    // TODO: at some point unify entrypoint per package.
    _ = @import("exec-spec-tests/execspectests.zig");
    _ = @import("types/types.zig");
    _ = @import("vm/vm.zig");
}
