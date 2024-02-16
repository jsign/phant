const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;

pub const ChainId = enum(u64) {
    SpecTest = 0,
    Mainnet = 1,
    Goerli = 5,
    Holesky = 17000,
    Kaustinen = 69420,
    Sepolia = 11155111,
};

pub const Config = struct {
    engine_port: u16 = 8551,
    network_id: u64 = @intFromEnum(ChainId.Mainnet),
};

const mainnetChainSpec = @embedFile("../chainspecs/mainnet.json");
const sepoliaChainSpec = @embedFile("../chainspecs/sepolia.json");

pub fn applyChainSpec(allocator: Allocator, cfg: *Config) !void {
    const options = json.ParseOptions{
        .ignore_unknown_fields = true,
    };
    switch (@as(ChainId, @enumFromInt(cfg.network_id))) {
        ChainId.Mainnet => cfg.* = (try json.parseFromSlice(Config, allocator, mainnetChainSpec, options)).value,
        ChainId.Sepolia => cfg.* = (try json.parseFromSlice(Config, allocator, sepoliaChainSpec, options)).value,
        else => std.debug.print("Using custom chain id: {}\n", .{cfg.network_id}),
    }
}
