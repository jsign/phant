const std = @import("std");
const types = @import("types.zig");
const Allocator = std.mem.Allocator;
const Hash32 = types.Hash32;
const Address = types.Address;
const LogsBloom = types.LogsBloom;

pub const Receipt = struct {
    succeeded: bool,
    cumulative_gas_used: u64,
    bloom: LogsBloom,
    logs: []Log,
};

pub const Log = struct {
    address: Address,
    topics: []Hash32,
    data: []u8,
};
