const std = @import("std");
const Allocator = std.mem.Allocator;
const common = @import("../common/common.zig");
const types = @import("types.zig");
const Address = types.Address;
const Bytecode = types.Bytecode;
const assert = std.debug.assert;

const log = std.log.scoped(.account_state);

const AccountState = @This();

allocator: Allocator,
addr: Address,
nonce: u256,
balance: u256,
code: Bytecode,
storage: std.AutoHashMap(u256, u256),

// init initializes an account state with the given values.
// deinit() must be called on the account state to free the storage.
pub fn init(allocator: Allocator, addr: Address, nonce: u256, balance: u256, code: Bytecode) !AccountState {
    return AccountState{
        .allocator = allocator,
        .addr = addr,
        .nonce = nonce,
        .balance = balance,
        .code = try allocator.dupe(u8, code),
        .storage = std.AutoHashMap(u256, u256).init(allocator),
    };
}

pub fn deinit(self: *AccountState) void {
    self.storage.deinit();
    self.allocator.free(self.code);
}

pub fn storage_get(self: *const AccountState, key: u256) ?u256 {
    return self.storage.get(key);
}

pub fn storage_set(self: *AccountState, key: u256, value: u256) !void {
    try self.storage.put(key, value);
}

const test_allocator = std.testing.allocator;
test "storage" {
    var account = try AccountState.init(test_allocator, common.hexToAddress("0x010142"), 0, 0, &[_]u8{});
    defer account.deinit();

    // Set key=0x42, val=0x43, and check get.
    try account.storage_set(0x42, 0x43);
    try std.testing.expect(account.storage_get(0x42) == 0x43);

    // Get a key that doesn't exist.
    if (account.storage_get(0x44)) |_| {
        return error.ExpectedError;
    }

    // Set existing key=0x42 to new value and get.
    try account.storage_set(0x42, 0x13);
    try std.testing.expect(account.storage_get(0x42) == 0x13);
}
