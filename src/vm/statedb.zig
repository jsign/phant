const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("../types/types.zig");
const Address = types.Address;
const AccountState = types.AccountState;

const log = std.log.scoped(.statedb);

const StateDB = @This();

const AccountDB = std.AutoHashMap(Address, AccountState);
db: AccountDB,

pub fn init(allocator: Allocator, accounts_state: []AccountState) !StateDB {
    var db = AccountDB.init(allocator);
    try db.ensureTotalCapacity(@intCast(accounts_state.len));

    for (accounts_state) |account| {
        db.putAssumeCapacityNoClobber(account.addr, account);
    }
    return StateDB{
        .db = db,
    };
}

pub fn get(self: *const StateDB, addr: Address) ?AccountState {
    return self.db.get(addr);
}

// TODO: get tests.
