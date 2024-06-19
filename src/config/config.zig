const std = @import("std");
const json = std.json;
const Allocator = std.mem.Allocator;
const ptable = @import("pretty-table");
const Table = ptable.Table;
const String = ptable.String;

pub const ChainId = enum(u64) {
    SpecTest = 0,
    Mainnet = 1,
    Goerli = 5,
    Holesky = 17000,
    Kaustinen = 69420,
    Sepolia = 11155111,
};

pub const Config = struct {
    ChainName: []const u8,
    chainId: u64 = @intFromEnum(ChainId.Mainnet),
    homesteadBlock: ?u64,
    daoForkBlock: ?u64,
    eip150Block: ?u64,
    eip155Block: ?u64,
    byzantiumBlock: ?u64,
    constantinopleBlock: ?u64,
    petersburgBlock: ?u64,
    istanbulBlock: ?u64,
    muirGlacierBlock: ?u64,
    berlinBlock: ?u64,
    londonBlock: ?u64,
    arrowGlacierBlock: ?u64,
    grayGlacierBlock: ?u64,
    // ttd: ?u256,
    // merged: bool,
    shanghaiTime: ?u64,
    // cancunTime: ?u64,
    // pragueTime: ?u64,
    // osakaTime: ?u64,

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
        var config: Config = undefined;
        const options = json.ParseOptions{
            .ignore_unknown_fields = true,
        };
        config = (try json.parseFromSlice(Config, allocator, chainspec, options)).value;
        return config;
    }

    pub fn default(allocator: Allocator) !Self {
        return fromChainSpec(mainnetChainSpec, allocator);
    }

    pub fn dump(self: *Self, allocator: Allocator) !void {
        const table = Table(2){
            .header = [_]String{ "Fork", "Block number" },
            .rows = &[_][2]String{
                .{ "Homestead", if (self.homesteadBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.homesteadBlock}) else "off" },
                .{ "DAO", if (self.homesteadBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.daoForkBlock}) else "off" },
            },
            .mode = .box,
        };
        std.log.info("{}\n", .{table});
    }
};

const mainnetChainSpec = @embedFile("../chainspecs/mainnet.json");
const sepoliaChainSpec = @embedFile("../chainspecs/sepolia.json");
