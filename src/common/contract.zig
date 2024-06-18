const std = @import("std");
const Allocator = std.mem.Allocator;
const rlp = @import("zig-rlp");
const types = @import("../types/types.zig");
const Keccak256 = std.crypto.hash.sha3.Keccak256;

// TODO: with careful calculation, we could avoid the allocator.
pub fn computeCREATEContractAddress(allocator: Allocator, address: types.Address, nonce: u64) !types.Address {
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try rlp.serialize(struct { addr: types.Address, nonce: u64 }, allocator, .{ .addr = address, .nonce = nonce }, &out);

    var computed_address: [Keccak256.digest_length]u8 = undefined;
    Keccak256.hash(out.items, &computed_address, .{});

    var padded_address: types.Address = std.mem.zeroes(types.Address);
    @memcpy(&padded_address, computed_address[12..]);

    return padded_address;
}

pub fn computeCREATE2ContractAddress(address: types.Address, salt: types.Bytes32, bytecode: []const u8) !types.Address {
    var preimage: [1 + address.len + salt.len + Keccak256.digest_length]u8 = undefined;
    preimage[0] = 0xFF;
    @memcpy(preimage[1..][0..address.len], &address);
    @memcpy(preimage[1 + address.len ..][0..salt.len], &salt);
    Keccak256.hash(bytecode, preimage[1 + address.len + salt.len ..], .{});

    return genContractAddress(&preimage);
}

fn genContractAddress(preimage: []const u8) types.Address {
    var computed_address: [Keccak256.digest_length]u8 = undefined;
    Keccak256.hash(preimage, &computed_address, .{});

    var padded_address: types.Address = std.mem.zeroes(types.Address);
    @memcpy(&padded_address, computed_address[12..]);

    return padded_address;
}
