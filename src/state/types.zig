const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("../types/types.zig");
const Bytes32 = types.Bytes32;
const Address = types.Address;

pub const AccountData = struct {
    nonce: u64,
    balance: u256,
    code: []const u8,
};

pub const AccountState = struct {
    allocator: Allocator,
    addr: Address,
    nonce: u64,
    balance: u256,
    code: []const u8,
    storage: std.AutoHashMap(u256, Bytes32),

    // init initializes an account state with the given values.
    // The caller must call deinit() when done.
    pub fn init(allocator: Allocator, addr: Address, nonce: u64, balance: u256, code: []const u8) !AccountState {
        return AccountState{
            .allocator = allocator,
            .addr = addr,
            .nonce = nonce,
            .balance = balance,
            .code = if (code.len > 0) try allocator.dupe(u8, code) else code,
            .storage = std.AutoHashMap(u256, Bytes32).init(allocator),
        };
    }

    pub fn deinit(self: *AccountState) void {
        self.storage.deinit();
        if (self.code.len > 0)
            self.allocator.free(self.code);
    }
};
