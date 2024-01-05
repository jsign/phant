const std = @import("std");
const types = @import("../types/types.zig");
const Allocator = std.mem.Allocator;
const Address = types.Address;
const AccountState = types.AccountState;
const log = std.log.scoped(.statedb);

const StateDB = @This();
allocator: Allocator,
db: AccountDB,

const AccountDB = std.AutoHashMap(Address, AccountState);

pub fn init(allocator: Allocator, accounts_state: []AccountState) !StateDB {
    var db = AccountDB.init(allocator);
    try db.ensureTotalCapacity(@intCast(accounts_state.len));

    for (accounts_state) |account| {
        db.putAssumeCapacityNoClobber(account.addr, account);
    }
    return StateDB{
        .allocator = allocator,
        .db = db,
    };
}

// TODO: return a more focused parameter (balance, code, nonce)
pub fn getAccount(self: *StateDB, addr: Address) !?AccountState {
    return try self.db.get(addr);
}

pub fn getStorage(self: *StateDB, addr: Address, key: u256) !u256 {
    const account = try self.getAccount(addr) orelse return 0;
    return try account.storage.get(key) orelse 0;
}

pub fn setStorage(self: *StateDB, addr: Address, key: u256, value: u256) !void {
    var account = try self.getAccount(addr) orelse return error.AccountDoesNotExist;
    try account.storage.put(key, value);
}

pub fn setBalance(self: *StateDB, addr: Address, balance: u256) !void {
    var account = try self.getAccount(addr);
    account.balance = balance;
}

pub fn incrementNonce(self: *StateDB, addr: Address) !void {
    var account = try self.getAccount(addr);
    account.nonce += 1;
}

pub fn getCode(self: *StateDB, addr: Address) !?[]const u8 {
    var account = try self.getAccount(addr) orelse return null;
    return account.code;
}

// TODO: get tests.
