const std = @import("std");
const Allocator = std.mem.Allocator;
const rlp = @import("zig-rlp");
const hasher = @import("../crypto/hasher.zig");
const types = @import("types.zig");
const Address = types.Address;

// TODO(jsign): create Transaction type that is the union of transaction types.
const Txn = @This();

pub const TxnData = struct {
    type: u8,
    chain_id: u256,
    nonce: u64,
    gas_price: u256,
    value: u256,
    to: ?Address,
    data: []const u8,
    gas_limit: u64,
};

data: TxnData,
v: u8,
r: u256,
s: u256,

// init initializes a transaction without signature fields.
// TODO(jsign): comment about data ownership.
pub fn init(
    type_: u8,
    chain_id: u256,
    nonce: u64,
    gas_price: u256,
    value: u256,
    to: ?Address,
    data: []const u8,
    gas_limit: u64,
) Txn {
    return @This(){
        .data = .{
            .type = type_,
            .chain_id = chain_id,
            .nonce = nonce,
            .gas_price = gas_price,
            .value = value,
            .to = to,
            .data = data,
            .gas_limit = gas_limit,
        },
        .v = 0,
        .r = 0,
        .s = 0,
    };
}

pub fn setSignature(self: *Txn, v: u8, r: u256, s: u256) void {
    self.*.v = v;
    self.*.r = r;
    self.*.s = s;
}

pub fn hash(self: Txn, allocator: Allocator) !types.Hash32 {
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();

    try rlp.serialize(TxnData, allocator, self.data, &out);

    return hasher.keccak256(out.items);
}
