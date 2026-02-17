const std = @import("std");
const types = @import("../types/types.zig");
const common = @import("../common/common.zig");
const state = @import("state.zig");
const Allocator = std.mem.Allocator;
const Address = types.Address;
const AddressSet = common.AddressSet;
const AddressKey = common.AddressKey;
const AddressKeySet = common.AddressKeySet;
const AccountData = state.AccountData;
const AccountState = state.AccountState;
const Bytes32 = types.Bytes32;
const ArrayList = std.array_list.Managed;
const log = std.log.scoped(.statedb);

pub const StateDB = struct {
    const AccountDB = std.AutoHashMap(Address, AccountState);

    allocator: Allocator,
    // original_db contains the state of the world when the transaction starts.
    // It assists in charging the right amount of gas for SSTORE.
    original_db: ?AccountDB = null,
    // db contains the state of the world while the current transaction is executing.
    // (i.e: current call scope)
    db: AccountDB,

    // Tx-scoped lists.
    touched_addresses: ArrayList(Address),
    accessed_accounts: AddressSet,
    accessed_storage_keys: AddressKeySet,
    created_accounts: AddressSet,
    accounts_to_destroy: AddressSet,
    transient_storage: std.AutoHashMap(AddressKey, Bytes32),

    pub fn init(allocator: Allocator, accounts: []const AccountState) !StateDB {
        var db = AccountDB.init(allocator);
        try db.ensureTotalCapacity(@intCast(accounts.len));
        for (accounts) |account| {
            db.putAssumeCapacityNoClobber(account.addr, account);
        }
        return .{
            .allocator = allocator,
            .db = db,
            .accessed_accounts = AddressSet.init(allocator),
            .accessed_storage_keys = AddressKeySet.init(allocator),
            .touched_addresses = ArrayList(Address).init(allocator),
            .created_accounts = AddressSet.init(allocator),
            .accounts_to_destroy = AddressSet.init(allocator),
            .transient_storage = std.AutoHashMap(AddressKey, Bytes32).init(allocator),
        };
    }

    pub fn deinit(self: *StateDB) void {
        var key_iterator = self.db.keyIterator();
        while (key_iterator.next()) |addr| {
            self.db.getPtr(addr.*).?.deinit();
        }
        self.db.deinit();

        self.accessed_accounts.deinit();
        self.accessed_storage_keys.deinit();
        self.created_accounts.deinit();
        self.accounts_to_destroy.deinit();

        if (self.original_db) |*original_db| {
            original_db.deinit();
        }
    }

    pub fn startTx(self: *StateDB) !void {
        if (self.original_db) |*original_db| {
            var it = original_db.iterator();
            while (it.next()) |kv| {
                kv.value_ptr.deinit();
            }
            original_db.deinit();
        }
        self.original_db = try dbDeepClone(self.allocator, &self.db);
        self.accessed_accounts.clearRetainingCapacity();
        self.accessed_storage_keys.clearRetainingCapacity();
        self.created_accounts.clearRetainingCapacity();
        self.accounts_to_destroy.clearRetainingCapacity();
        self.transient_storage.clearRetainingCapacity();
    }

    pub fn isEmpty(self: StateDB, addr: Address) bool {
        const account = self.getAccountOpt(addr) orelse return false;
        return account.nonce == 0 and account.code.len == 0 and account.balance == 0;
    }

    pub fn addTouchedAddress(self: *StateDB, addr: Address) !void {
        try self.touched_addresses.append(addr);
    }

    pub fn getAccountOpt(self: StateDB, addr: Address) ?AccountData {
        if (self.db.capacity() == 0 and self.db.count() == 0) return null;
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
        const account = self.db.get(addr) orelse return std.mem.zeroes(Bytes32);
        return account.storage.get(key) orelse std.mem.zeroes(Bytes32);
    }

    pub fn getOriginalStorage(self: *StateDB, addr: Address, key: u256) Bytes32 {
        const account = self.original_db.?.get(addr) orelse return std.mem.zeroes(Bytes32);
        return account.storage.get(key) orelse std.mem.zeroes(Bytes32);
    }

    pub fn getAllStorage(self: *StateDB, addr: Address) ?std.AutoHashMap(u256, Bytes32) {
        const account = self.db.get(addr) orelse return null;
        return account.storage;
    }

    pub fn setStorage(self: *StateDB, addr: Address, key: u256, value: Bytes32) !void {
        var account = self.db.getPtr(addr) orelse blk: {
            try self.db.put(addr, try @import("state.zig").AccountState.init(self.allocator, addr, 0, 0, &[_]u8{}));
            break :blk self.db.getPtr(addr).?;
        };
        if (std.mem.eql(u8, &value, &std.mem.zeroes(Bytes32))) {
            _ = account.storage.remove(key);
            return;
        }
        try account.storage.put(key, value);
    }

    pub fn setBalance(self: *StateDB, addr: Address, balance: u256) !void {
        const account = self.db.getPtr(addr);
        if (account) |acc| {
            acc.balance = balance;
            return;
        }
        try self.db.put(addr, try AccountState.init(self.allocator, addr, 0, balance, &[_]u8{}));
    }

    pub fn incrementNonce(self: *StateDB, addr: Address) !void {
        var account = self.db.getPtr(addr) orelse blk: {
            try self.db.put(addr, try @import("state.zig").AccountState.init(self.allocator, addr, 0, 0, &[_]u8{}));
            break :blk self.db.getPtr(addr).?;
        };
        account.nonce += 1;
    }

    pub fn destroyAccount(self: *StateDB, addr: Address) void {
        _ = self.db.remove(addr);
    }

    pub fn setContractCode(self: *StateDB, addr: Address, code: []const u8) !void {
        const account = self.db.getPtr(addr);
        if (account) |acc| {
            if (acc.code.len > 0)
                return error.AccountAlreadyHasCode;
            acc.code = try acc.allocator.dupe(u8, code);
            return;
        }
        try self.db.put(addr, try AccountState.init(self.allocator, addr, 0, 0, code));
    }

    pub fn accountExistsAndIsEmpty(self: *StateDB, addr: Address) bool {
        const account = self.db.get(addr) orelse return false;
        return account.nonce == 0 and account.balance == 0 and account.code.len == 0;
    }

    pub fn accessedAccountsContains(self: *StateDB, addr: Address) bool {
        return self.accessed_accounts.contains(addr);
    }

    pub fn putAccessedAccount(self: *StateDB, addr: Address) !void {
        try self.accessed_accounts.put(addr, {});
    }

    pub fn accessedStorageKeysContains(self: *StateDB, addrkey: AddressKey) bool {
        return self.accessed_storage_keys.contains(addrkey);
    }

    pub fn putAccessedStorageKeys(self: *StateDB, addrkey: AddressKey) !void {
        try self.accessed_storage_keys.put(addrkey, {});
    }

    pub fn markCreated(self: *StateDB, addr: Address) !void {
        try self.created_accounts.put(addr, {});
    }

    pub fn markSelfDestructed(self: *StateDB, addr: Address) !void {
        try self.accounts_to_destroy.put(addr, {});
    }

    pub fn wasCreatedInTx(self: *StateDB, addr: Address) bool {
        return self.created_accounts.contains(addr);
    }

    pub fn getTransientStorage(self: *StateDB, addr: Address, key: Bytes32) Bytes32 {
        const ak = AddressKey{ .address = addr, .key = key };
        return self.transient_storage.get(ak) orelse std.mem.zeroes(Bytes32);
    }

    pub fn setTransientStorage(self: *StateDB, addr: Address, key: Bytes32, value: Bytes32) !void {
        const ak = AddressKey{ .address = addr, .key = key };
        try self.transient_storage.put(ak, value);
    }

    pub fn snapshot(self: *StateDB) !StateDB {
        // TODO: while simple this is quite inefficient.
        // A much smarter way is doing some "diff" style snapshotting or similar.
        return StateDB{
            .allocator = self.allocator,
            .db = try dbDeepClone(self.allocator, &self.db),
            .original_db = if (self.original_db) |*odb| try dbDeepClone(self.allocator, odb) else null,
            .accessed_accounts = try self.accessed_accounts.clone(),
            .accessed_storage_keys = try self.accessed_storage_keys.clone(),
            .touched_addresses = try self.touched_addresses.clone(),
            .created_accounts = try self.created_accounts.clone(),
            .accounts_to_destroy = try self.accounts_to_destroy.clone(),
            .transient_storage = try self.transient_storage.clone(),
        };
    }

    /// Restore state from a snapshot, replacing the current state entirely.
    /// The snapshot is consumed (moved into self).
    pub fn restoreFrom(self: *StateDB, snap: *StateDB) void {
        // Free current state
        {
            var it = self.db.iterator();
            while (it.next()) |kv| {
                kv.value_ptr.deinit();
            }
        }
        self.db.deinit();
        if (self.original_db) |*odb| {
            var it2 = odb.iterator();
            while (it2.next()) |kv| {
                kv.value_ptr.deinit();
            }
            odb.deinit();
        }
        self.accessed_accounts.deinit();
        self.accessed_storage_keys.deinit();
        self.touched_addresses.deinit();
        self.created_accounts.deinit();
        self.accounts_to_destroy.deinit();
        self.transient_storage.deinit();

        // Move snapshot fields into self
        self.db = snap.db;
        self.original_db = snap.original_db;
        self.accessed_accounts = snap.accessed_accounts;
        self.accessed_storage_keys = snap.accessed_storage_keys;
        self.touched_addresses = snap.touched_addresses;
        self.created_accounts = snap.created_accounts;
        self.accounts_to_destroy = snap.accounts_to_destroy;
        self.transient_storage = snap.transient_storage;

        // Invalidate snapshot to prevent double-free on deinit
        snap.db = AccountDB.init(snap.allocator);
        snap.original_db = null;
        snap.accessed_accounts = AddressSet.init(snap.allocator);
        snap.accessed_storage_keys = AddressKeySet.init(snap.allocator);
        snap.touched_addresses = ArrayList(Address).init(snap.allocator);
        snap.created_accounts = AddressSet.init(snap.allocator);
        snap.accounts_to_destroy = AddressSet.init(snap.allocator);
        snap.transient_storage = std.AutoHashMap(AddressKey, Bytes32).init(snap.allocator);
    }

    fn dbDeepClone(allocator: Allocator, db: *AccountDB) !AccountDB {
        var ret = AccountDB.init(allocator);
        try ret.ensureTotalCapacity(db.capacity());

        var it = db.iterator();
        while (it.next()) |kv| {
            ret.putAssumeCapacityNoClobber(kv.key_ptr.*, try kv.value_ptr.clone());
        }
        return ret;
    }
};
