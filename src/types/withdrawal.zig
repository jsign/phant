const std = @import("std");
const types = @import("types.zig");
const rlp = @import("zig-rlp");
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

pub const Withdrawal = struct {
    index: u64,
    validator: u64,
    address: types.Address,
    amount: u64,

    // encode returns the RLP encoding of the withdrawal. The caller is responsible for freeing the returned slice.
    pub fn encode(self: Withdrawal, allocator: Allocator) ![]const u8 {
        var out = ArrayList(u8).init(allocator);
        defer out.deinit();
        try rlp.serialize(Withdrawal, allocator, self, &out);

        return out.toOwnedSlice();
    }
};
