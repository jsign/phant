const std = @import("std");
const Allocator = std.mem.Allocator;
const util = @import("../util/util.zig");
const types = @import("types.zig");
const Address = types.Address;
const Bytecode = types.Bytecode;

const log = std.log.scoped(.account_state);

const AccountState = @This();

addr: Address,
nonce: u256,
balance: u256,
code: Bytecode,
storage: std.AutoHashMap(u256, u256),

// init initializes an account state with the given values.
// The bytecode slice isn't owned by the account state, so it must outlive the account state.
// deinit() must be called on the account state to free the storage.
//
// TODO(jsign): consider copying code to make it less brittle, or clarify in comment.
pub fn init(allocator: Allocator, addr: Address, nonce: u256, balance: u256, code: Bytecode) AccountState {
    return AccountState{
        .addr = addr,
        .nonce = nonce,
        .balance = balance,
        .code = code,
        .storage = std.AutoHashMap(u256, u256).init(allocator),
    };
}

pub fn deinit(self: *AccountState) void {
    self.storage.deinit();
}

pub fn storage_get(self: *const AccountState, key: u256) ?u256 {
    log.debug("get storage key=0x{x}", .{key});
    return self.storage.get(key);
}

pub fn storage_set(self: *AccountState, key: u256, value: u256) !void {
    log.debug("set storage key=0x{x}, value=0x{x}", .{ key, value });
    try self.storage.put(key, value);
}

const test_allocator = std.testing.allocator;
test "storage" {
    var account = AccountState.init(test_allocator, util.hex_to_address("0x010142"), 0, 0, &[_]u8{});
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
