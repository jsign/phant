const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;
// pretty-table disabled for now

pub const ChainId = enum(u64) {
    SpecTest = 0,
    Mainnet = 1,
    Goerli = 5,
    Testing = 1337,
    Holesky = 17000,
    Kaustinen = 69420,
    Sepolia = 11155111,
};

pub const ChainConfig = struct {
    ChainName: []const u8,
    chainId: ChainId = ChainId.Mainnet,
    homesteadBlock: ?u64 = null,
    daoForkBlock: ?u64 = null,
    eip150Block: ?u64 = null,
    eip155Block: ?u64 = null,
    byzantiumBlock: ?u64 = null,
    constantinopleBlock: ?u64 = null,
    petersburgBlock: ?u64 = null,
    istanbulBlock: ?u64 = null,
    muirGlacierBlock: ?u64 = null,
    berlinBlock: ?u64 = null,
    londonBlock: ?u64 = null,
    arrowGlacierBlock: ?u64 = null,
    grayGlacierBlock: ?u64 = null,
    terminalTotalDifficulty: ?u256 = null,
    terminalTotalDifficultyPassed: ?bool = null,
    shanghaiTime: ?u64 = null,
    cancunTime: ?u64 = null,
    pragueTime: ?u64 = null,
    osakaTime: ?u64 = null,

    const Self = @This();

    pub fn fromChainId(id: ChainId, allocator: Allocator) !Self {
        return switch (id) {
            .Mainnet => fromChainSpec(mainnetChainSpec, allocator),
            .Sepolia => fromChainSpec(sepoliaChainSpec, allocator),
            .Goerli => error.DeprecatedNetwork,
            else => error.UnsupportedNetwork,
        };
    }

    pub fn fromChainSpec(chainspec: []const u8, allocator: Allocator) !Self {
        var config: ChainConfig = undefined;
        const options = json.ParseOptions{
            .ignore_unknown_fields = true,
            .allocate = .alloc_if_needed,
        };

        config = (try json.parseFromSlice(ChainConfig, allocator, chainspec, options)).value;
        return config;
    }

    pub fn default(allocator: Allocator) !Self {
        return fromChainSpec(mainnetChainSpec, allocator);
    }

    pub fn dump(self: *Self, allocator: Allocator) !void {
        _ = self;
        _ = allocator;
    }
};

const mainnetChainSpec = @embedFile("../chainspecs/mainnet.json");
const sepoliaChainSpec = @embedFile("../chainspecs/sepolia.json");
