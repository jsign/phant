const std = @import("std");
const types = @import("../types/types.zig");
const Allocator = std.mem.Allocator;
const Address = types.Address;
const AccountState = types.AccountState;
const log = std.log.scoped(.statedb);

// TODO: create container.

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
pub fn getAccount(self: *StateDB, addr: Address) ?AccountState {
    return self.db.get(addr);
}

pub fn getStorage(self: *StateDB, addr: Address, key: u256) !u256 {
    const account = self.getAccount(addr) orelse return 0;
    return try account.storage.get(key) orelse 0;
}

pub fn setStorage(self: *StateDB, addr: Address, key: u256, value: u256) !void {
    var account = self.getAccount(addr) orelse return error.AccountDoesNotExist;
    try account.storage.put(key, value);
}

pub fn setBalance(self: *StateDB, addr: Address, balance: u256) !void {
    var account = self.db.getPtr(addr);
    if (account) |acc| {
        acc.balance = balance;
        return;
    }
    try self.db.put(try AccountState.init(self.allocator, addr, 0, balance, &[_]u8{}));
}

pub fn incrementNonce(self: *StateDB, addr: Address) !void {
    var account = try self.getAccount(addr) orelse return error.AccountDoesNotExist;
    account.nonce += 1;
}

pub fn getCode(self: *StateDB, addr: Address) []const u8 {
    var account = self.getAccount(addr) orelse &[_]u8{};
    return account.code;
}

pub fn snapshot(self: StateDB) StateDB {
    // TODO: while simple this is quite inefficient.
    // A much smarter way is doing some "diff" style snapshotting or similar.
    return StateDB{
        .allocator = self.allocator,
        .db = self.db.cloneWithAllocator(self.allocator),
    };
}
