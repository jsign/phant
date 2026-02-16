const std = @import("std");
const Fork = @import("../fork.zig");
const lib = @import("../../lib.zig");
const Hash32 = lib.types.Hash32;
const StateDB = lib.state.StateDB;
const Address = lib.types.Address;

const blockhash_contract_addr: Address = .{ 0x00, 0x00, 0xf9, 0x08, 0x27, 0xf1, 0xc5, 0x3a, 0x10, 0xcb, 0x7a, 0x02, 0x33, 0x5b, 0x17, 0x53, 0x20, 0x00, 0x29, 0x35 };
const history_size: u64 = 8192;

const vtable = Fork.VTable{
    .update_parent_block_hash = update_parent_block_hash,
    .get_parent_block_hash = get_parent_block_hash,
    .deinit = deinit,
};

const PragueFork = struct {
    fork: Fork = Fork{
        .vtable = &vtable,
    },

    state_db: *StateDB,
    allocator: std.mem.Allocator,
};

fn update_parent_block_hash(self: *Fork, num: u64, hash: Hash32) anyerror!void {
    const prague_fork: *PragueFork = @fieldParentPtr("fork", self);
    const slot: u256 = @intCast(num % history_size);
    try prague_fork.state_db.setStorage(blockhash_contract_addr, slot, hash);
}

fn get_parent_block_hash(self: *Fork, index: u64) !Hash32 {
    const prague_fork: *PragueFork = @fieldParentPtr("fork", self);
    const slot: u256 = @intCast(index % history_size);
    return prague_fork.state_db.getStorage(blockhash_contract_addr, slot);
}

// This method takes a parent fork and activate all the
// Prague-specific methods, superseding the previous fork.
pub fn enablePrague(state_db: *StateDB, _: ?*Fork, allocator: std.mem.Allocator) !*Fork {
    var prague_fork = try allocator.create(PragueFork);
    prague_fork.allocator = allocator;
    prague_fork.state_db = state_db;
    prague_fork.fork = Fork{ .vtable = &vtable };
    return &prague_fork.fork;
}

fn deinit(self: *Fork) void {
    const prague_fork: *PragueFork = @fieldParentPtr("fork", self);
    prague_fork.allocator.destroy(prague_fork);
}

// a helper function to deploy the 2935 contract on a testnet.
pub fn deployContract(self: *Fork) !void {
    const prague_fork: *PragueFork = @fieldParentPtr("fork", self);
    try prague_fork.state_db.db.put(blockhash_contract_addr, try lib.state.AccountState.init(prague_fork.allocator, blockhash_contract_addr, 1, 0, &[0]u8{}));
}
