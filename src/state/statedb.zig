const std = @import("std");
const types = @import("../types/types.zig");
const statetypes = @import("types.zig");
const Bytes32 = types.Bytes32;
const Allocator = std.mem.Allocator;
const Address = types.Address;
const log = std.log.scoped(.statedb);

pub const AccountData = statetypes.AccountData;
pub const AccountState = statetypes.AccountState;

pub const StateDB = struct {
    const AccountDB = std.AutoHashMap(Address, AccountState);

    allocator: Allocator,
    db: AccountDB,

    pub fn init(allocator: Allocator, accounts: []AccountState) !StateDB {
        var db = AccountDB.init(allocator);
        try db.ensureTotalCapacity(@intCast(accounts.len));
        for (accounts) |account| {
            db.putAssumeCapacityNoClobber(account.addr, account);
        }
        return .{ .allocator = allocator, .db = db };
    }

    pub fn deinit(self: *StateDB) void {
        self.db.deinit();
    }

    pub fn getAccountOpt(self: *StateDB, addr: Address) ?AccountData {
        const account_data = self.db.get(addr) orelse return null;
        return .{
            .nonce = account_data.nonce,
            .balance = account_data.balance,
            .code = account_data.code,
        };
    }

    pub fn getAccount(self: *StateDB, addr: Address) AccountData {
        return self.getAccountOpt(addr) orelse AccountData{
            .nonce = 0,
            .balance = 0,
            .code = &[_]u8{},
        };
    }

    pub fn getStorage(self: *StateDB, addr: Address, key: u256) Bytes32 {
        const account = self.db.get(addr) orelse return 0;
        return account.storage.get(key) orelse 0;
    }

    pub fn setStorage(self: *StateDB, addr: Address, key: u256, value: Bytes32) !void {
        var account = self.db.get(addr) orelse return error.AccountDoesNotExist;
        try account.storage.put(key, value);
    }

    pub fn setBalance(self: *StateDB, addr: Address, balance: u256) !void {
        var account = self.db.getPtr(addr);
        if (account) |acc| {
            acc.balance = balance;
            return;
        }
        try self.db.put(addr, try AccountState.init(self.allocator, addr, 0, balance, &[_]u8{}));
    }

    pub fn incrementNonce(self: *StateDB, addr: Address) !void {
        var account = self.db.getPtr(addr) orelse return error.AccountDoesNotExist;
        account.nonce += 1;
    }

    pub fn destroyAccount(self: *StateDB, addr: Address) void {
        _ = self.db.remove(addr);
    }

    pub fn accountExistsAndIsEmpty(self: *StateDB, addr: Address) bool {
        const account = self.db.get(addr) orelse return false;
        return account.nonce == 0 and account.balance == 0 and account.code.len == 0;
    }

    pub fn snapshot(self: StateDB) !StateDB {
        // TODO: while simple this is quite inefficient.
        // A much smarter way is doing some "diff" style snapshotting or similar.
        return StateDB{
            .allocator = self.allocator,
            .db = try self.db.cloneWithAllocator(self.allocator),
        };
    }

    pub fn getAllStorage(self: *StateDB, addr: Address) ?std.AutoHashMap(u256, Bytes32) {
        const account = self.db.get(addr) orelse return null;
        return account.storage;
    }
};
