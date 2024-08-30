const lib = @import("../lib.zig");
const Hash32 = lib.types.Hash32;
const Fork = @This();
pub const base = @import("./forks/base.zig");
pub const prague = @import("./forks/prague.zig");

vtable: *const VTable,

pub const VTable = struct {
    update_parent_block_hash: *const fn (self: *Fork, num: u64, hash: Hash32) anyerror!void,
    get_parent_block_hash: *const fn (self: *Fork, index: u64) anyerror!Hash32,
    deinit: *const fn (self: *Fork) void,
};

// Used to update the parent hash at the end of a block execution
pub fn update_parent_block_hash(self: *Fork, num: u64, hash: Hash32) !void {
    return self.vtable.update_parent_block_hash(self, num, hash);
}

// Used to get the block hash of a parent when implementing the
// BLOCKHASH instruction.
pub fn get_parent_block_hash(self: *Fork, index: u64) !Hash32 {
    return self.vtable.get_parent_block_hash(self, index);
}

pub fn deinit(self: *Fork) void {
    self.vtable.deinit(self);
}
