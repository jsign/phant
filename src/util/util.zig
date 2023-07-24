const std = @import("std");
const vm = @import("../vm/types.zig");

pub fn hex_to_address(comptime account_hex: []const u8) vm.Address {
    const account_hex_strip = if (std.mem.startsWith(u8, account_hex, "0x")) account_hex[2..] else account_hex[0..];
    var account = std.mem.zeroes([32]u8);
    _ = std.fmt.hexToBytes(&account, account_hex_strip) catch unreachable;
    return account;
}
