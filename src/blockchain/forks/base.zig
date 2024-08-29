const std = @import("std");
const Fork = @import("../fork.zig");
const lib = @import("../../lib.zig");
const Hash32 = lib.types.Hash32;

const base_fork_vtable = Fork.VTable{
    .update_parent_block_hash = update_parent_block_hash,
    .get_parent_block_hash = get_parent_block_hash,
};

const BaseFork = struct {
    const Self = @This();

    fork: Fork = .{
        .vtable = &base_fork_vtable,
    },

    written: u64 = 0,
    block_hashes: [256]Hash32 = [_]Hash32{[_]u8{0} ** 32} ** 256,

    fn init(self: *Self) void {
        self.written = 0;
        self.fork.vtable = &base_fork_vtable;
    }
};

fn update_parent_block_hash(self: *Fork, num: u64, hash: Hash32) anyerror!void {
    var base_fork: *BaseFork = @fieldParentPtr("fork", self);
    if (num != base_fork.written) {
        return error.NonSequentialParentUpdate;
    }

    base_fork.block_hashes[base_fork.written % base_fork.block_hashes.len] = hash;
    base_fork.written += 1;
}

fn get_parent_block_hash(self: *Fork, index: u64) !Hash32 {
    const base_fork: *BaseFork = @fieldParentPtr("fork", self);
    if (index > base_fork.written or index + base_fork.block_hashes.len < base_fork.written) {
        return std.mem.zeroes(Hash32);
    }

    return base_fork.block_hashes[index % base_fork.block_hashes.len];
}

pub fn newBaseFork(allocator: std.mem.Allocator) *Fork {
    var base_fork = allocator.create(BaseFork) catch @panic("could not allocate fork");
    base_fork.init();
    return &base_fork.fork;
}
