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
        const table = Table(3){
            .header = [_]String{ "Fork", "Block number", "Timestamp" },
            .rows = &[_][3]String{
                .{ "Homestead", if (self.homesteadBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.homesteadBlock}) else "inactive", "na" },
                .{ "DAO", if (self.homesteadBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.daoForkBlock}) else "inactive", "na" },
                .{ "Byzantium", if (self.byzantiumBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.byzantiumBlock}) else "inactive", "na" },
                .{ "Constantinople", if (self.constantinopleBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.constantinopleBlock}) else "inactive", "na" },
                .{ "Petersburg", if (self.petersburgBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.petersburgBlock}) else "inactive", "na" },
                .{ "Istanbul", if (self.istanbulBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.istanbulBlock}) else "inactive", "na" },
                .{ "Muir Glacier", if (self.muirGlacierBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.muirGlacierBlock}) else "inactive", "na" },
                .{ "Berlin", if (self.berlinBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.berlinBlock}) else "inactive", "na" },
                .{ "London", if (self.londonBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.londonBlock}) else "inactive", "na" },
                .{ "Arrow Glacier", if (self.arrowGlacierBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.arrowGlacierBlock}) else "inactive", "na" },
                .{ "Gray Glacier", if (self.grayGlacierBlock != null) try std.fmt.allocPrint(allocator, "{any}", .{self.grayGlacierBlock}) else "inactive", "na" },
                .{ "Shanghai", "na", if (self.shanghaiTime != null) try std.fmt.allocPrint(allocator, "{any}", .{self.shanghaiTime}) else "inactive" },
                .{ "Cancun", "na", if (self.cancunTime != null) try std.fmt.allocPrint(allocator, "{any}", .{self.cancunTime}) else "inactive" },
                .{ "Prague", "na", if (self.pragueTime != null) try std.fmt.allocPrint(allocator, "{any}", .{self.pragueTime}) else "inactive" },
                .{ "Osaka", "na", if (self.osakaTime != null) try std.fmt.allocPrint(allocator, "{any}", .{self.osakaTime}) else "inactive" },
            },
            .mode = .box,
        };
        std.log.info("{}\n", .{table});
    }
};

const mainnetChainSpec = @embedFile("../chainspecs/mainnet.json");
const sepoliaChainSpec = @embedFile("../chainspecs/sepolia.json");
