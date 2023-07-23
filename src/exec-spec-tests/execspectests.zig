const std = @import("std");
const rlp = @import("zig-rlp");
const Allocator = std.mem.Allocator;
var test_allocator = std.testing.allocator;
const Block = @import("../block/block.zig").Block;

const HexString = []const u8;

pub const Fixture = struct {
    const FixtureType = std.json.ArrayHashMap(FixtureTest);
    tests: std.json.Parsed(FixtureType),

    pub fn new_from_bytes(allocator: Allocator, bytes: []const u8) !Fixture {
        const tests = try std.json.parseFromSlice(FixtureType, allocator, bytes, std.json.ParseOptions{ .ignore_unknown_fields = true, .allocate = std.json.AllocWhen.alloc_always });

        return Fixture{ .tests = tests };
    }

    pub fn deinit(self: *Fixture) void {
        self.tests.deinit();
        self.tests = undefined;
    }
};

pub const FixtureTest = struct {
    _info: struct {
        @"filling-transition-tool": []const u8,
        @"filling-block-build-tool": []const u8,
    },
    blocks: []const struct {
        rlp: []const u8,
        blockHeader: BlockHeaderHex,
    },
    genesisBlockHeader: BlockHeaderHex,
    genesisRLP: HexString,
    lastblockhash: HexString,
    network: []const u8,
    pre: ChainState,
    postState: ChainState,
    sealEngine: []const u8,
};

pub const ChainState = std.json.ArrayHashMap(AccountState);

pub const BlockHeaderHex = struct {
    parentHash: HexString,
    uncleHash: HexString,
    coinbase: HexString,
    stateRoot: HexString,
    transactionsTrie: HexString,
    receiptTrie: HexString,
    bloom: HexString,
    difficulty: HexString,
    number: HexString,
    gasLimit: HexString,
    gasUsed: HexString,
    timestamp: HexString,
    extraData: HexString,
    mixHash: HexString,
    nonce: HexString,
    hash: HexString,
};

pub const AccountState = struct {
    nonce: HexString,
    balance: HexString,
    code: HexString,
    storage: AccountStorage,
};

const AccountStorage = std.json.ArrayHashMap(HexString);

test "execution-spec-tests" {
    var ft = try Fixture.new_from_bytes(test_allocator, @embedFile("fixtures/exec-spec-fixture.json"));
    defer ft.deinit();

    var it = ft.tests.value.map.iterator();
    while (it.next()) |entry| {
        for (entry.value_ptr.*.blocks) |block| {
            var out = try test_allocator.alloc(u8, block.rlp.len * 2);
            defer test_allocator.free(out);
            const bytez = try std.fmt.hexToBytes(out, block.rlp[2..]);

            var block_header = std.mem.zeroes(Block);
            _ = try rlp.deserialize(Block, bytez, &block_header);
        }
    }
}
