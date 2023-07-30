const std = @import("std");
const types = @import("types.zig");
const Address = types.Address;

// TODO(jsign): consider using union to support txntypes
type: u8,
chain_id: u256,
nonce: u64,
gas_price: u256,
value: u256,
to: ?Address,
data: []const u8,
gas_limit: u64,

// TODO(jsign): comment about data ownership.
pub fn init(type_: u8, chain_id: u256, nonce: u64, gas_price: u256, value: u256, to: ?Address, data: []const u8, gas_limit: u64) @This() {
    return @This(){
        .type = type_,
        .chain_id = chain_id,
        .nonce = nonce,
        .gas_price = gas_price,
        .value = value,
        .to = to,
        .data = data,
        .gas_limit = gas_limit,
    };
}

// TODO(jsign): use some secp256k1 library.
pub fn get_from(_: *const @This()) Address {
    const from: Address = comptime blk: {
        var buf: Address = undefined;
        _ = std.fmt.hexToBytes(&buf, "a94f5374Fce5edBC8E2a8697C15331677e6EbF0B") catch unreachable;
        break :blk buf;
    };
    return from;
}

// TODO(jsign): add helper to get txn hash.
