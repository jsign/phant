const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("../block/verkle.zig");
const vmtypes = @import("../vm/vm.zig").types;
const log = std.log.scoped(.statedb);

const AccountDB = std.AutoHashMap(vmtypes.Address, vmtypes.AccountState);

db: AccountDB,

pub fn init(allocator: Allocator, accounts_state: []vmtypes.AccountState) !@This() {
    log.debug("creating statedb with {d} accounts", .{accounts_state.len});
    var db = AccountDB.init(allocator);
    try db.ensureTotalCapacity(@intCast(accounts_state.len));

    for (accounts_state) |account| {
        log.debug("addr -> {s}", .{std.fmt.fmtSliceHexLower(&account.addr)});
        db.putAssumeCapacityNoClobber(account.addr, account);
    }
    return @This(){
        .db = db,
    };
}

pub fn get(self: *const @This(), addr: vmtypes.Address) ?vmtypes.AccountState {
    log.debug("get address {s}", .{std.fmt.fmtSliceHexLower(&addr)});
    return self.db.get(addr);
}

// TODO: get tests.
