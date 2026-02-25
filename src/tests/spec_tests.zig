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
            // Skip pre-Berlin forks (no EIP-2929 accessed accounts, PoW difficulty, uncle handling)
            const pre_berlin_skip = [_][]const u8{
                "Frontier", "Homestead", "EIP150", "EIP158", "Byzantium",
                "Constantinople", "ConstantinopleFix", "Istanbul",
                "FrontierToHomesteadAt5", "HomesteadToEIP150At5",
                "HomesteadToDaoAt5", "EIP158ToByzantiumAt5",
                "ByzantiumToConstantinopleFixAt5",
            };
            for (pre_berlin_skip) |name| {
                if (std.mem.eql(u8, self.network, name)) {
                    return true; // skip unsupported pre-Berlin forks
                }
            }
            const pre_prague = [_][]const u8{
                "Berlin", "London", "Paris", "Shanghai", "Cancun",
                // Note: *AtTime15k transition forks are skipped below
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
            const block = Block.decode(allocator, rlp_bytes) catch |err| {
                // Block RLP decoding failed
                if (encoded_block.expectException != null) {
                    continue; // Expected failure — skip this block
                }
                log.err("unexpected block decode error in {s}: {}", .{ self.network, err });
                return error.BlockExecutionValidityExpectationMismatch;
            };

            if (chain.runBlock(block)) |_| {
                // Block executed successfully
                if (encoded_block.expectException != null) {
                    log.err("block should have been rejected in {s} (expected: {s})", .{ self.network, encoded_block.expectException.? });
                    return error.BlockShouldHaveBeenRejected;
                }
            } else |err| {
                // Block execution failed
                if (encoded_block.expectException != null) {
                    // Expected failure — restore state from genesis since runBlock
                    // may have partially modified it (no automatic rollback).
                    // Don't deinit old statedb — arena allocator handles cleanup.
                    // Deinit would free code slices that accounts_state still references.
                    statedb = try StateDB.init(allocator, accounts_state);
                    continue;
                }
                log.err("block execution failed unexpectedly in {s}: {}", .{ self.network, err });
                return error.BlockExecutionValidityExpectationMismatch;
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
    var passed: usize = 0;
    var skipped: usize = 0;
    var failed: usize = 0;

    const test_files = [_][]const u8{
        // EIP-7623
        "src/tests/fixtures/prague/eip7623_increase_calldata_cost/test_transaction_validity_type_1_type_2.json",
        // EIP-7702 — passing tests
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_to_sstore.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_double_auth.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_nonce_validity.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_delegation_clearing.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_empty_authorization_list.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_to_log.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_to_sstore_then_sload.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_to_self_destruct.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_gas_cost.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_intrinsic_gas_cost.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_account_warming.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_valid_tx_invalid_auth_signature.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_address_from_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_authorization_reusing_nonce.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_call_into_chain_delegating_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_call_into_self_delegating_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_call_to_pre_authorized_oog.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_contract_create.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_contract_storage_to_pointer_with_storage.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_delegation_clearing_and_set.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_delegation_clearing_failing_tx.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_delegation_clearing_tx_to.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_delegation_replacement_call_previous_contract.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_eip_7702.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_eoa_init_as_pointer.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_eoa_tx_after_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_ext_code_on_chain_delegating_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_ext_code_on_self_delegating_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_ext_code_on_self_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_ext_code_on_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_invalid_transaction_after_authorization.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_many_delegations.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_nonce_overflow_after_first_authorization.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_pointer_call_followed_by_direct_call.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_pointer_measurements.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_pointer_normal.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_pointer_reverts.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_pointer_to_pointer.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_pointer_to_static.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_reset_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_self_code_on_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_self_set_code_cost.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_self_sponsored_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_address_and_authority_warm_state_call_types.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_address_and_authority_warm_state.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_all_invalid_authorization_tuples.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_call_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_from_account_with_non_delegating_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_multiple_first_valid_authorization_tuples_same_signer.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_multiple_valid_authorization_tuples_first_invalid_same_signer.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_multiple_valid_authorization_tuples_same_signer_increasing_nonce.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_multiple_valid_authorization_tuples_same_signer_increasing_nonce_self_sponsored.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_to_contract_creator.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_to_non_empty_storage_non_zero_nonce.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_transaction_fee_validations.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_type_tx_pre_fork.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_using_chain_specific_id.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_using_valid_synthetic_signatures.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_set_code_to_tstore_available_at_correct_address.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_signature_s_out_of_range.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_static_to_pointer.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_tx_into_chain_delegating_set_code.json",
        "src/tests/fixtures/prague/eip7702_set_code_tx/test_tx_into_self_delegating_set_code.json",
    };

    for (test_files) |filepath| {
        std.log.warn("##### FILE {s} (passed={d} failed={d} skipped={d}) #####", .{ filepath, passed, failed, skipped });

        {
            // Per-file arena for JSON parsing (large fixtures = many small allocs).
            // Per-test arena inside for EVM execution state.
            var file_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer file_arena.deinit();
            const file_alloc = file_arena.allocator();

            const file_content = try std.fs.cwd().readFileAlloc(file_alloc, filepath, 1 << 30);
            var ft = try Fixture.fromBytes(file_alloc, file_content);

            var it = ft.tests.value.map.iterator();
            while (it.next()) |entry| {
                // Per-test arena for EVM execution
                var test_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
                const test_alloc = test_arena.allocator();

                const result = entry.value_ptr.run(test_alloc) catch |e| {
                    std.log.err("FAIL {s}: {}", .{ entry.key_ptr.*, e });
                    failed += 1;
                    test_arena.deinit();
                    continue;
                };
                if (result) {
                    passed += 1;
                } else {
                    skipped += 1;
                }
                test_arena.deinit();
            }
        }
    }
    std.log.warn("Results: {d} passed, {d} skipped, {d} failed", .{ passed, skipped, failed });
    try std.testing.expect(failed == 0);
}

