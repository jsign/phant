const std = @import("std");
const types = @import("../types/types.zig");
const Address = types.Address;
const evmc = @cImport({
    @cInclude("evmone.h");
});

// to_evmc_address transforms an Address or ?Address into an evmc_address.
pub fn to_evmc_address(address: anytype) evmc.struct_evmc_address {
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

pub fn from_evmc_address(address: evmc.struct_evmc_address) Address {
    return address.bytes;
}

pub fn to_evmc_bytes32(num: u256) evmc.evmc_bytes32 {
    var evmc_num = evmc.struct_evmc_bytes32{
        .bytes = undefined,
    };
    std.mem.writeIntSliceBig(u256, &evmc_num.bytes, num);
    return evmc_num;
}
