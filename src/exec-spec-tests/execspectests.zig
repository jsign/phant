const std = @import("std");
const rlp = @import("zig-rlp");
const Allocator = std.mem.Allocator;
const types = @import("../types/types.zig");
const Address = types.Address;
const AccountState = types.AccountState;
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const vm = @import("../vm/vm.zig");
const VM = vm.VM;
const StateDB = vm.StateDB;
const TxnSigner = @import("../signer/signer.zig").TxnSigner;
const ecdsa = @import("../crypto/ecdsa.zig");
const log = std.log.scoped(.execspectests);

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

        // 1. We parse the account state "prestate" from the test, and create our
        // statedb with this initial state of accounts.
        var accounts_state = blk: {
            var accounts_state = try allocator.alloc(AccountState, self.pre.map.count());
            var it = self.pre.map.iterator();
            var i: usize = 0;
            while (it.next()) |entry| {
                accounts_state[i] = try entry.value_ptr.*.to_vm_accountstate(allocator, entry.key_ptr.*);
                i = i + 1;
            }
            break :blk accounts_state;
        };
        var db = try StateDB.init(allocator, accounts_state);
        var evm = VM.init(&db);

        // 2. Execute blocks.
        const txn_signer = try TxnSigner.init();
        for (self.blocks) |encoded_block| {
            var out = try allocator.alloc(u8, encoded_block.rlp.len / 2);
            defer allocator.free(out);
            const rlp_bytes = try std.fmt.hexToBytes(out, encoded_block.rlp[2..]);

            const block = try Block.init(rlp_bytes);

            var txns = try allocator.alloc(Transaction, encoded_block.transactions.len);
            defer allocator.free(txns);
            for (encoded_block.transactions, 0..) |tx_hex, i| {
                txns[i] = try tx_hex.to_vm_transaction(allocator, txn_signer);
            }

            try evm.run_block(allocator, txn_signer, block, txns);
        }

        // 3. Verify that the post state matches what the fixture `postState` claims is true.
        var it = self.postState.map.iterator();
        while (it.next()) |entry| {
            var exp_account_state: AccountState = try entry.value_ptr.*.to_vm_accountstate(allocator, entry.key_ptr.*);
            std.debug.print("checking account state: {s}\n", .{std.fmt.fmtSliceHexLower(&exp_account_state.addr)});
            const got_account_state = try db.get(exp_account_state.addr);
            if (!std.mem.eql(u8, &got_account_state.addr, &exp_account_state.addr)) {
                return error.post_state_addr_mismatch;
            }
            if (got_account_state.nonce != exp_account_state.nonce) {
                log.err("expected nonce {d} but got {d}", .{ exp_account_state.nonce, got_account_state.nonce });
                return error.post_state_nonce_mismatch;
            }
            if (got_account_state.balance != exp_account_state.balance) {
                log.err("expected balance {d} but got {d}", .{ exp_account_state.balance, got_account_state.balance });
                return error.post_state_balance_mismatch;
            }
            if (got_account_state.storage.count() != exp_account_state.storage.count()) {
                return error.post_state_storage_size_mismatch;
            }
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

    pub fn to_vm_transaction(self: TransactionHex, allocator: Allocator, txn_signer: TxnSigner) !Transaction {
        const type_ = try std.fmt.parseInt(u8, self.type[2..], 16);
        const chain_id = try std.fmt.parseInt(u256, self.chainId[2..], 16);
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

        var txn = Transaction.init(type_, chain_id, nonce, gas_price, value, to, data, gas_limit);
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

    pub fn to_vm_accountstate(self: *const AccountStateHex, allocator: Allocator, addr_hex: []const u8) !AccountState {
        const nonce = try std.fmt.parseInt(u256, self.nonce[2..], 16);
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

            try account.storage_set(key, value);
        }

        return account;
    }
};

const AccountStorageHex = std.json.ArrayHashMap(HexString);

var test_allocator = std.testing.allocator;
test "execution-spec-tests" {
    var ft = try Fixture.new_from_bytes(test_allocator, @embedFile("fixtures/exec-spec-fixture.json"));
    defer ft.deinit();

    var it = ft.tests.value.map.iterator();
    var count: usize = 0;

    while (it.next()) |entry| {
        log.debug("##### Executing fixture {s} #####", .{entry.key_ptr.*});
        try std.testing.expect(try entry.value_ptr.*.run(test_allocator));
        count += 1;

        // TODO: Only run the first test for now. Then we can enable all and continue with the integration.
        if (count == 1) {
            break;
        }
    }
}
