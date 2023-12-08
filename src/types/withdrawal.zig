const std = @import("std");
const types = @import("types.zig");

pub const Withdrawal = struct {
    index: u64,
    validator: u64,
    address: types.Address,
    amount: u64,
};
