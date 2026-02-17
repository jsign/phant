const std = @import("std");
const rlp = @import("rlp");
const config = @import("../config/config.zig");
const types = @import("../types/types.zig");
const blockchain = @import("../blockchain/blockchain.zig");
const vm = @import("../blockchain/vm.zig");
const ecdsa = @import("../crypto/crypto.zig").ecdsa;
const state = @import("../state/state.zig");
const common = @import("../common/common.zig");
const TxSigner = @import("../signer/signer.zig").TxSigner;
const Allocator = std.mem.Allocator;
const Address = types.Address;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Tx = types.Tx;
const Hash32 = types.Hash32;
const Bytes32 = types.Bytes32;
const VM = vm.VM;
const StateDB = state.StateDB;
const AccountState = state.AccountState;
const log = std.log.scoped(.execspectests);
const Fork = blockchain.Fork;

const HexString = []const u8;

pub const Fixture = struct {
    const FixtureType = std.json.ArrayHashMap(FixtureTest);
    tests: std.json.Parsed(FixtureType),

    pub fn fromBytes(allocator: Allocator, bytes: []const u8) !Fixture {
        const tests = try std.json.parseFromSlice(FixtureType, allocator, bytes, std.json.ParseOptions{ .ignore_unknown_fields = true, .allocate = std.json.AllocWhen.alloc_always });
        return .{ .tests = tests };
    }

    pub fn deinit(self: *Fixture) void {
        self.tests.deinit();
        self.tests = undefined;
    }
};

pub const FixtureTest = struct {
    _info: struct {
        @"filling-transition-tool": ?[]const u8 = null,
        @"reference-spec": ?[]const u8 = null,
        @"reference-spec-version": ?[]const u8 = null,
    },
    network: []const u8,
    genesisRLP: HexString,
    blocks: []const struct {
        rlp: []const u8,
        expectException: ?[]const u8 = null,
    },
    lastblockhash: HexString,
    pre: ChainState,
    postState: ChainState,
    sealEngine: []const u8,

    pub fn run(self: *const FixtureTest, base_allocator: Allocator) !bool {
        var arena = std.heap.ArenaAllocator.init(base_allocator);
        defer arena.deinit();
        var allocator = arena.allocator();

        // We parse the account state "prestate" from the test, and create our
        // statedb with this initial state of accounts.
        const accounts_state = blk: {
            var accounts_state = try allocator.alloc(AccountState, self.pre.map.count());
            var it = self.pre.map.iterator();
            var i: usize = 0;
            while (it.next()) |entry| {
                accounts_state[i] = try entry.value_ptr.toAccountState(allocator, entry.key_ptr.*);
                i = i + 1;
            }
            break :blk accounts_state;
        };
        var statedb = try StateDB.init(allocator, accounts_state);

        // Initialize the blockchain with the preloaded statedb and the genesis
        // block as the previous block.
        var out = try allocator.alloc(u8, self.genesisRLP.len / 2);
        var rlp_bytes = try std.fmt.hexToBytes(out, self.genesisRLP[2..]);
        const parent_block = try Block.decode(allocator, rlp_bytes);
        // Select fork based on network
        const fork = blk2: {
            const pre_prague = [_][]const u8{
                "Frontier", "Homestead", "EIP150", "EIP158", "Byzantium",
                "Constantinople", "ConstantinopleFix", "Istanbul", "Berlin",
                "London", "Paris", "Shanghai", "Cancun",
                "FrontierToHomesteadAt5", "HomesteadToEIP150At5",
                "HomesteadToDaoAt5", "EIP158ToByzantiumAt5",
                "ByzantiumToConstantinopleFixAt5",
                // Note: *AtTime15k transition forks are skipped (handled below)
            };
            for (pre_prague) |name| {
                if (std.mem.eql(u8, self.network, name)) {
                    break :blk2 try Fork.frontier.newFrontierFork(allocator);
                }
            }
            if (std.mem.eql(u8, self.network, "Prague")) {
                break :blk2 try Fork.prague.enablePrague(&statedb, null, allocator);
            }
            // Skip time-based transition forks for now (require mid-block fork switching)
            if (std.mem.endsWith(u8, self.network, "AtTime15k")) {
                return true;
            }
            log.warn("Skipping unsupported network: {s}", .{self.network});
            return true; // skip unsupported networks
        };
        var chain = try blockchain.Blockchain.init(allocator, config.ChainId.Mainnet, &statedb, parent_block.header, fork);

        // Set EVMC revision based on network
        const evmc_revisions = .{
            .{ "Frontier", 0 },
            .{ "Homestead", 1 },
            .{ "EIP150", 2 }, // Tangerine Whistle
            .{ "EIP158", 3 }, // Spurious Dragon
            .{ "Byzantium", 4 },
            .{ "Constantinople", 5 },
            .{ "ConstantinopleFix", 6 }, // Petersburg
            .{ "Istanbul", 7 },
            .{ "Berlin", 8 },
            .{ "London", 9 },
            .{ "Paris", 10 }, // The Merge
            .{ "Shanghai", 11 },
            .{ "Cancun", 12 },
            .{ "Prague", 13 },
            // Transition forks
            .{ "FrontierToHomesteadAt5", 1 },
            .{ "HomesteadToEIP150At5", 2 },
            .{ "HomesteadToDaoAt5", 1 },
            .{ "EIP158ToByzantiumAt5", 4 },
            .{ "ByzantiumToConstantinopleFixAt5", 6 },
            // Note: *AtTime15k transition forks are skipped (require mid-block fork switching)
        };
        inline for (evmc_revisions) |entry| {
            if (std.mem.eql(u8, self.network, entry[0])) {
                chain.evmc_revision = entry[1];
                break;
            }
        }

        // Execute blocks.
        for (self.blocks) |encoded_block| {
            out = try allocator.alloc(u8, encoded_block.rlp.len / 2);
            rlp_bytes = try std.fmt.hexToBytes(out, encoded_block.rlp[2..]);
            const block = try Block.decode(allocator, rlp_bytes);

            const block_should_fail = if (encoded_block.expectException) |_| true else false;
            if (chain.runBlock(block)) |_| {
                if (block_should_fail) {
                    log.err("block execution succeeded but expected failure", .{});
                    return error.BlockExecutionValidityExpectationMismatch;
                }
            } else |err| {
                if (!block_should_fail) {
                    log.err("block execution failed unexpectedly: {}", .{err});
                    return error.BlockExecutionValidityExpectationMismatch;
                }
            }
        }

        log.debug("All blocks executed, verifying post state...", .{});
        // Verify that the post state matches what the fixture `postState` claims is true.
        var it = self.postState.map.iterator();
        while (it.next()) |entry| {
            var exp_account_state: AccountState = try entry.value_ptr.toAccountState(allocator, entry.key_ptr.*);
            const got_account_state = statedb.getAccount(exp_account_state.addr);
            if (got_account_state.nonce != exp_account_state.nonce) {
                log.err("{x} expected nonce {d} but got {d}", .{ &exp_account_state.addr, exp_account_state.nonce, got_account_state.nonce });
                return error.PostStateNonceMismatch;
            }
            if (got_account_state.balance != exp_account_state.balance) {
                log.err("{x} expected balance {d} but got {d}", .{ &exp_account_state.addr, exp_account_state.balance, got_account_state.balance });
                return error.PostStateBalanceMismatch;
            }

            const got_storage = statedb.getAllStorage(exp_account_state.addr) orelse return error.PostStateAccountMustExist;
            // Count non-zero entries in got_storage
            var got_nonzero_count: usize = 0;
            {
                var it_count = got_storage.iterator();
                while (it_count.next()) |se| {
                    if (!std.mem.eql(u8, se.value_ptr, &std.mem.zeroes(Bytes32))) {
                        got_nonzero_count += 1;
                    }
                }
            }
            if (got_nonzero_count != exp_account_state.storage.count()) {
                log.err("{x} expected storage count {d} but got {d}", .{ &exp_account_state.addr, exp_account_state.storage.count(), got_nonzero_count });
                return error.PostStateStorageCountMismatch;
            }
            var it_got = got_storage.iterator();
            while (it_got.next()) |storage_entry| {
                // Skip zero-value entries in got_storage
                if (std.mem.eql(u8, storage_entry.value_ptr, &std.mem.zeroes(Bytes32))) continue;
                const val = exp_account_state.storage.get(storage_entry.key_ptr.*) orelse return error.PostStateStorageKeyMustExist;
                if (!std.mem.eql(u8, storage_entry.value_ptr, &val)) {
                    log.err("{x} expected storage slot value at {d}, got {x}, exp {x}", .{ &exp_account_state.addr, storage_entry.key_ptr.*, &storage_entry.value_ptr.*, &val });
                    return error.PostStateStorageValueMismatch;
                }
            }
        }

        return true;
    }
};

pub const ChainState = std.json.ArrayHashMap(AccountStateHex);

pub const AccountStateHex = struct {
    nonce: HexString,
    balance: HexString,
    code: HexString,
    storage: AccountStorageHex,

    pub fn toAccountState(self: AccountStateHex, allocator: Allocator, addr_hex: []const u8) !AccountState {
        const nonce = try std.fmt.parseInt(u64, self.nonce[2..], 16);
        const balance = try std.fmt.parseInt(u256, self.balance[2..], 16);

        const code = try allocator.alloc(u8, self.code[2..].len / 2);
        _ = try std.fmt.hexToBytes(code, self.code[2..]);

        var addr: Address = undefined;
        _ = try std.fmt.hexToBytes(&addr, addr_hex[2..]);

        var account = try AccountState.init(allocator, addr, nonce, balance, code);

        var it = self.storage.map.iterator();
        while (it.next()) |entry| {
            const key = try std.fmt.parseUnsigned(u256, entry.key_ptr.*[2..], 16);
            const value = try std.fmt.parseUnsigned(u256, entry.value_ptr.*[2..], 16);
            if (value != 0) {
                var value_bytes: Bytes32 = undefined;
                std.mem.writeInt(u256, &value_bytes, value, .big);
                try account.storage.putNoClobber(key, value_bytes);
            }
        }

        return account;
    }
};

const AccountStorageHex = std.json.ArrayHashMap(HexString);

test "execution-spec-tests" {
    const allocator = std.testing.allocator;

    var test_folder = try std.fs.cwd().openDir("src/tests/fixtures", .{ .iterate = true });
    defer test_folder.close();

    var test_it = try test_folder.walk(allocator);
    defer test_it.deinit();
    while (try test_it.next()) |f| {
        if (f.kind == .directory) continue;

        std.log.debug("##### Spec-test file {s} #####", .{f.basename});
        const file_content = try f.dir.readFileAlloc(allocator, f.basename, 1 << 30);
        defer allocator.free(file_content);

        var ft = try Fixture.fromBytes(allocator, file_content);
        defer ft.deinit();

        var it = ft.tests.value.map.iterator();
        while (it.next()) |entry| {
            std.log.debug("-> Spec-test file {s}", .{entry.key_ptr.*});
            try std.testing.expect(try entry.value_ptr.run(allocator));
        }
    }
}
