const std = @import("std");
const rlp = @import("zig-rlp");
const Allocator = std.mem.Allocator;
const Block = @import("../block/block.zig").Block;
const statedb = @import("../statedb/statedb.zig");
const vmtypes = @import("../vm/types.zig");

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

    pub fn run(self: *const FixtureTest, allocator: Allocator) !bool {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();

        var it = self.pre.map.iterator();
        while (it.next()) |entry| {
            var account_state = try entry.value_ptr.*.to_vm_accountstate(allocator, entry.key_ptr.*);
            _ = account_state;
        }

        it = self.postState.map.iterator();
        while (it.next()) |entry| {
            var account_state = try entry.value_ptr.*.to_vm_accountstate(allocator, entry.key_ptr.*);
            _ = account_state;
        }

        return false;
    }
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

    // TODO(jsign): add init() and add assertions about lengths.

    pub fn to_vm_accountstate(self: *const AccountState, allocator: Allocator, addr: []const u8) !vmtypes.AccountState {
        const nonce = std.mem.readInt(u256, @as(*const [32]u8, @ptrCast(self.nonce)), std.builtin.Endian.Big);

        // TODO(jsign): helper to avoid repetition?
        const balance = std.mem.readInt(u256, @as(*const [32]u8, @ptrCast(self.balance)), std.builtin.Endian.Big);

        var code = try allocator.alloc(u8, self.code.len * 2);
        defer allocator.free(code);
        _ = try std.fmt.hexToBytes(code, self.code[2..]);

        var account = vmtypes.AccountState.init(allocator, @as(*const [32]u8, @ptrCast(addr)).*, nonce, balance, code);
        defer account.deinit();

        var it = self.storage.map.iterator();
        while (it.next()) |entry| {
            var key_bytes: [32]u8 = std.mem.zeroes([32]u8);
            var key_bytes_aligned = key_bytes[32 - (entry.key_ptr.*.len - 2) / 2 ..];
            _ = try std.fmt.hexToBytes(key_bytes_aligned, entry.key_ptr.*[2..]);
            const key = std.mem.readInt(u256, &key_bytes, std.builtin.Endian.Big);

            var value_bytes: [32]u8 = std.mem.zeroes([32]u8);
            var value_bytes_aligned = value_bytes[32 - (entry.value_ptr.*.len - 2) / 2 ..];
            _ = try std.fmt.hexToBytes(value_bytes_aligned, entry.value_ptr.*[2..]);
            const value = std.mem.readInt(u256, &value_bytes, std.builtin.Endian.Big);

            try account.storage_set(key, value);
        }

        return account;
    }
};

const AccountStorage = std.json.ArrayHashMap(HexString);

var test_allocator = std.testing.allocator;
test "execution-spec-tests" {
    var ft = try Fixture.new_from_bytes(test_allocator, @embedFile("fixtures/exec-spec-fixture.json"));
    defer ft.deinit();

    var it = ft.tests.value.map.iterator();
    while (it.next()) |entry| {
        const ok = try entry.value_ptr.*.run(test_allocator);
        _ = ok;
        for (entry.value_ptr.*.blocks) |block| {
            var out = try test_allocator.alloc(u8, block.rlp.len * 2);
            defer test_allocator.free(out);
            const bytez = try std.fmt.hexToBytes(out, block.rlp[2..]);

            var block_header = std.mem.zeroes(Block);
            _ = try rlp.deserialize(Block, bytez, &block_header);
        }
    }
}
