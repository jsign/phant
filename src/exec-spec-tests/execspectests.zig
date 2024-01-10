const std = @import("std");
const rlp = @import("rlp");
const config = @import("../config/config.zig");
const types = @import("../types/types.zig");
const blockchain = @import("../blockchain/blockchain.zig");
const vm = @import("../blockchain/vm.zig");
const ecdsa = @import("../crypto/crypto.zig").ecdsa;
const state = @import("../state/state.zig");
const TxnSigner = @import("../signer/signer.zig").TxnSigner;
const Allocator = std.mem.Allocator;
const Address = types.Address;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Txn = types.Txn;
const Hash32 = types.Hash32;
const Bytes32 = types.Bytes32;
const VM = vm.VM;
const StateDB = state.StateDB;
const AccountState = state.AccountState;
const log = std.log.scoped(.execspectests);

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
        @"filling-transition-tool": []const u8,
        @"filling-block-build-tool": []const u8,
    },
    blocks: []const struct {
        rlp: []const u8,
        blockHeader: BlockHeaderHex,
        transactions: []TransactionHex,
    },
    genesisBlockHeader: BlockHeaderHex,
    genesisRLP: HexString,
    lastblockhash: HexString,
    network: []const u8,
    pre: ChainState,
    postState: ChainState,
    sealEngine: []const u8,

    pub fn run(self: *const FixtureTest, base_allocator: Allocator) !bool {
        var arena = std.heap.ArenaAllocator.init(base_allocator);
        defer arena.deinit();
        var allocator = arena.allocator();

        // We parse the account state "prestate" from the test, and create our
        // statedb with this initial state of accounts.
        var accounts_state = blk: {
            var accounts_state = try allocator.alloc(AccountState, self.pre.map.count());
            var it = self.pre.map.iterator();
            var i: usize = 0;
            while (it.next()) |entry| {
                accounts_state[i] = try entry.value_ptr.*.toAccountState(allocator, entry.key_ptr.*);
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
        var chain = try blockchain.Blockchain.init(allocator, config.ChainId.SpecTest, &statedb, parent_block.header, std.mem.zeroes([256]Hash32));

        // Execute blocks.
        for (self.blocks) |encoded_block| {
            out = try allocator.alloc(u8, encoded_block.rlp.len / 2);
            rlp_bytes = try std.fmt.hexToBytes(out, encoded_block.rlp[2..]);
            const block = try Block.decode(allocator, rlp_bytes);
            try chain.runBlock(block);
        }

        // Verify that the post state matches what the fixture `postState` claims is true.
        var it = self.postState.map.iterator();
        while (it.next()) |entry| {
            var exp_account_state: AccountState = try entry.value_ptr.*.toAccountState(allocator, entry.key_ptr.*);
            std.debug.print("checking account state: {s}\n", .{std.fmt.fmtSliceHexLower(&exp_account_state.addr)});
            const got_account_state = statedb.getAccount(exp_account_state.addr);
            if (got_account_state.nonce != exp_account_state.nonce) {
                log.err("expected nonce {d} but got {d}", .{ exp_account_state.nonce, got_account_state.nonce });
                return error.PostStateNonceMismatch;
            }
            if (got_account_state.balance != exp_account_state.balance) {
                log.err("expected balance {d} but got {d}", .{ exp_account_state.balance, got_account_state.balance });
                return error.PostStateBalanceMismatch;
            }

            const got_storage = statedb.getAllStorage(exp_account_state.addr) orelse return error.PostStateAccountMustExist;
            if (got_storage.count() != exp_account_state.storage.count()) {
                log.err("expected storage count {d} but got {d}", .{ exp_account_state.storage.count(), got_storage.count() });
                return error.PostStateStorageCountMismatch;
            }
            // TODO: check each storage entry matches.
        }
        // TODO(jsign): verify gas used.

        return true;
    }
};

pub const ChainState = std.json.ArrayHashMap(AccountStateHex);

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

pub const TransactionHex = struct {
    type: HexString,
    chainId: HexString,
    nonce: HexString,
    gasPrice: HexString,
    value: HexString,
    to: HexString,
    protected: bool,
    secretKey: HexString,
    data: HexString,
    gasLimit: HexString,

    pub fn toTx(self: TransactionHex, allocator: Allocator, txn_signer: TxnSigner) !Txn {
        const type_ = try std.fmt.parseInt(u8, self.type[2..], 16);
        std.debug.assert(type_ == 0);
        const chain_id = try std.fmt.parseInt(u64, self.chainId[2..], 16);
        if (chain_id != txn_signer.chain_id) {
            return error.InvalidChainId;
        }
        const nonce = try std.fmt.parseUnsigned(u64, self.nonce[2..], 16);
        const gas_price = try std.fmt.parseUnsigned(u256, self.gasPrice[2..], 16);
        const value = try std.fmt.parseUnsigned(u256, self.value[2..], 16);
        var to: ?Address = null;
        if (self.to[2..].len != 0) {
            to = std.mem.zeroes(Address);
            _ = try std.fmt.hexToBytes(&to.?, self.to[2..]);
        }
        var data = try allocator.alloc(u8, self.data[2..].len / 2);
        _ = try std.fmt.hexToBytes(data, self.data[2..]);
        const gas_limit = try std.fmt.parseUnsigned(u64, self.gasLimit[2..], 16);

        var txn = Txn.initLegacyTxn(nonce, gas_price, value, to, data, gas_limit);
        var privkey: ecdsa.PrivateKey = undefined;
        _ = try std.fmt.hexToBytes(&privkey, self.secretKey[2..]);
        const sig = try txn_signer.sign(allocator, txn, privkey);
        txn.setSignature(sig.v, sig.r, sig.s);

        return txn;
    }
};

pub const AccountStateHex = struct {
    nonce: HexString,
    balance: HexString,
    code: HexString,
    storage: AccountStorageHex,

    // TODO(jsign): add init() and add assertions about lengths.

    pub fn toAccountState(self: *const AccountStateHex, allocator: Allocator, addr_hex: []const u8) !AccountState {
        const nonce = try std.fmt.parseInt(u64, self.nonce[2..], 16);
        const balance = try std.fmt.parseInt(u256, self.balance[2..], 16);

        var code = try allocator.alloc(u8, self.code[2..].len / 2);
        // TODO(jsign): check this.
        //defer allocator.free(code);
        _ = try std.fmt.hexToBytes(code, self.code[2..]);

        var addr: Address = undefined;
        _ = try std.fmt.hexToBytes(&addr, addr_hex[2..]);

        var account = try AccountState.init(allocator, addr, nonce, balance, code);

        var it = self.storage.map.iterator();
        while (it.next()) |entry| {
            const key = try std.fmt.parseUnsigned(u256, entry.key_ptr.*[2..], 16);
            const value = try std.fmt.parseUnsigned(u256, entry.value_ptr.*[2..], 16);
            var value_bytes: Bytes32 = undefined;
            std.mem.writeInt(u256, &value_bytes, value, .Big);
            try account.storage.putNoClobber(key, value_bytes);
        }

        return account;
    }
};

const AccountStorageHex = std.json.ArrayHashMap(HexString);

var test_allocator = std.testing.allocator;
test "execution-spec-tests" {
    var ft = try Fixture.fromBytes(test_allocator, @embedFile("fixtures/exec-spec-fixture.json"));
    defer ft.deinit();

    var it = ft.tests.value.map.iterator();
    var count: usize = 0;
    while (it.next()) |entry| {
        try std.testing.expect(try entry.value_ptr.*.run(test_allocator));
        count += 1;

        // TODO: Only run the first test for now. Then we can enable all and continue with the integration.
        if (count == 1) {
            break;
        }
    }
}
