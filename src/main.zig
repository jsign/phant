const std = @import("std");
const evmonehost = @import("host/host.zig");
const evmc = @cImport({
    @cInclude("evmc/evmc.h");
});
const evmone = @cImport({
    @cInclude("evmone.h");
});

pub fn main() !void {
    const vm = evmone.evmc_create_evmone();
    if (vm == null) {
        @panic("Failed to create EVMOne VM");
    }
    std.debug.print("EVMOne info: name={s}, version={s}, abi_version={d}\n", .{ vm.*.name, vm.*.version, vm.*.abi_version });

    var host = evmonehost.newHost();

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

    const message: evmc.struct_evmc_message = .{
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

    if (vm.*.execute) |exec| {
        var result = exec(vm, @ptrCast(&host), null, evmc.EVMC_SHANGHAI, @ptrCast(&message), @ptrCast(&code), code.len);
        std.debug.print("Result: status_code={}, gas_left={}\n", .{ result.status_code, result.gas_left });
    }
}
