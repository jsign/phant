const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("../types/types.zig");
const Address = types.Address;
const AccountState = types.AccountState;

const log = std.log.scoped(.statedb);

const StateDB = @This();

const AccountDB = std.AutoHashMap(Address, AccountState);

allocator: Allocator,
db: AccountDB,

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

pub fn getAccount(self: *StateDB, addr: Address) !*AccountState {
    var res = try self.db.getOrPut(addr);
    if (res.found_existing) {
        return res.value_ptr;
    }
    res.value_ptr.* = try AccountState.init(self.allocator, addr, 0, 0, &[_]u8{});

    return res.value_ptr;
}

pub fn setStorage(self: *StateDB, addr: Address, key: u256, value: u256) !void {
    var account = try self.getAccount(addr);
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

pub fn getCode(self: *StateDB, addr: Address) ![]const u8 {
    var account = try self.get(addr);
    return account.code;
}

// TODO: get tests.