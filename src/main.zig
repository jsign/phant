const std = @import("std");
const evmonehost = @import("vm/evmchost.zig");
const evmc = @cImport({
    @cInclude("evmc/evmc.h");
});
const evmone = @cImport({
    @cInclude("evmone.h");
});
const vmtypes = @import("vm/vm.zig").types;
const StateDb = @import("statedb/statedb.zig");

pub fn main() !void {
    std.log.info("Welcome to phant! 🐘", .{});

    const vm = evmone.evmc_create_evmone();
    if (vm == null) {
        @panic("Failed to create EVMOne VM");
    }
    std.log.info("evmone info: name={s}, version={s}, abi_version={d}", .{ vm.*.name, vm.*.version, vm.*.abi_version });

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();
    var statedb = try StateDb.init(allocator, &[_]vmtypes.AccountState{});
    var host = evmonehost.init(&statedb);

    const code = [_]u8{
        0x61, 0x41, 0x42,
        0x31,
    };

    const addr = evmc.struct_evmc_address{
        .bytes = [_]u8{0x0} ** 10 ++ [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10 },
    };
    const addr2 = evmc.struct_evmc_address{
        .bytes = [_]u8{0x0} ** 10 ++ [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x11 },
    };

    const message = evmc.struct_evmc_message{
        .kind = evmc.EVMC_CALL,
        .flags = 0,
        .depth = 0,
        .gas = 10_000,
        .recipient = addr2,
        .sender = addr,
        .input_data = &[_]u8{},
        .input_size = 0,
        .value = .{
            .bytes = [_]u8{0} ** 32,
        },
        .create2_salt = .{
            .bytes = [_]u8{0} ** 32,
        },
        .code_address = addr2,
    };
    std.log.info("0x{} bytecode: {} (PUSH2 0x4142; BALANCE;)", .{ std.fmt.fmtSliceHexLower(&message.recipient.bytes), std.fmt.fmtSliceHexLower(&code) });
    std.log.info("executing message -> gas={}, sender=0x{}, recipient=0x{}", .{ message.gas, std.fmt.fmtSliceHexLower(&message.sender.bytes), std.fmt.fmtSliceHexLower(&message.recipient.bytes) });

    if (vm.*.execute) |exec| {
        var result = exec(vm, @ptrCast(&host.evmc_host), null, evmc.EVMC_SHANGHAI, @ptrCast(&message), @ptrCast(&code), code.len);
        std.log.info("execution result -> status_code={}, gas_left={}", .{ result.status_code, result.gas_left });
    }
}

test "tests" {
    std.testing.log_level = .debug;

    // TODO: at some point unify entrypoint per package.
    _ = @import("statedb/statedb.zig");
    _ = @import("vm/evmchost.zig");
    _ = @import("block/block.zig");
    _ = @import("exec-spec-tests/execspectests.zig");
    _ = @import("vm/types.zig");
    _ = @import("vm/vm.zig");
}
