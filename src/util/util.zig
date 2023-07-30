const std = @import("std");
const vmtypes = @import("../vm/vm.zig").types;
const Address = vmtypes.Address;

pub fn hex_to_address(account_hex: []const u8) Address {
    const account_hex_strip = if (std.mem.startsWith(u8, account_hex, "0x")) account_hex[2..] else account_hex[0..];
    var address = std.mem.zeroes(Address);
    _ = std.fmt.hexToBytes(&address, account_hex_strip) catch unreachable;
    return address;
}
