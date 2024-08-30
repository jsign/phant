const std = @import("std");
const Fork = @import("../fork.zig");
const lib = @import("../../lib.zig");
const Hash32 = lib.types.Hash32;

const base_fork_vtable = Fork.VTable{
    .update_parent_block_hash = update_parent_block_hash,
    .get_parent_block_hash = get_parent_block_hash,
    .deinit = deinit,
};

const BaseFork = struct {
    const Self = @This();

    fork: Fork = .{
        .vtable = &base_fork_vtable,
    },

    allocator: std.mem.Allocator,
    next_block_hash_index: u64 = 0, // index of the next block hash to be written
    block_hashes: [256]Hash32 = [_]Hash32{[_]u8{0} ** 32} ** 256,

    fn init(self: *Self) void {
        self.next_block_hash_index = 0;
        self.fork.vtable = &base_fork_vtable;
    }
};

fn update_parent_block_hash(self: *Fork, block_num: u64, hash: Hash32) anyerror!void {
    var base_fork: *BaseFork = @fieldParentPtr("fork", self);
    if (block_num != base_fork.next_block_hash_index) {
        return error.NonSequentialParentUpdate;
    }

    base_fork.block_hashes[base_fork.next_block_hash_index % base_fork.block_hashes.len] = hash;
    base_fork.next_block_hash_index += 1;
}

fn get_parent_block_hash(self: *Fork, block_num: u64) !Hash32 {
    const base_fork: *BaseFork = @fieldParentPtr("fork", self);
    if (block_num > base_fork.next_block_hash_index or block_num + base_fork.block_hashes.len < base_fork.next_block_hash_index) {
        return std.mem.zeroes(Hash32);
    }

    return base_fork.block_hashes[block_num % base_fork.block_hashes.len];
}

pub fn newBaseFork(allocator: std.mem.Allocator) !*Fork {
    var base_fork = try allocator.create(BaseFork);
    base_fork.init();
    base_fork.allocator = allocator;
    return &base_fork.fork;
}

fn deinit(self: *Fork) void {
    var base_fork: *BaseFork = @fieldParentPtr("fork", self);
    base_fork.allocator.destroy(base_fork);
}
