const Fork = @import("../fork.zig");
const lib = @import("../../lib.zig");
const Hash32 = lib.types.Hash32;
const StateDB = lib.state.StateDB;
const self = @This();
const Address = lib.types.Address;

const system_addr: Address = [_]u8{0xff} ** 19 ++ [_]u8{0xfe};
const history_size: u64 = 8192;
var state_db: ?*StateDB = null;

const vtable = Fork.VTable{
    .update_parent_block_hash = update_parent_block_hash,
    .get_parent_block_hash = get_parent_block_hash,
};

fn update_parent_block_hash(_: *Fork, num: u64, hash: Hash32) anyerror!void {
    if (self.state_db) |state_db_ptr| {
        const slot: u256 = @intCast(num % history_size);
        try state_db_ptr.setStorage(self.system_addr, slot, hash);
    }

    return error.UninitializedStateDB;
}

fn get_parent_block_hash(_: *Fork, index: u64) !Hash32 {
    if (self.state_db) |state_db_ptr| {
        const slot: u256 = @intCast(index % history_size);
        return state_db_ptr.getStorage(self.system_addr, slot);
    }

    return error.UninitializedStateDB;
}

// This method takes a parent fork and activate all the
// Prague-specific methods, superseding the previous fork.
pub fn enablePrague(_: *StateDB, _: *Fork) Fork {
    return Fork{
        .vtable = &vtable,
    };
}
