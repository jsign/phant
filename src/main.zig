const std = @import("std");
const types = @import("types/types.zig");
const ecdsa = @import("crypto/ecdsa.zig");
const config = @import("config/config.zig");
const AccountState = types.AccountState;
const Address = types.Address;
const VM = @import("blockchain/vm.zig").VM;
const StateDB = @import("state/statedb.zig");
const Block = types.Block;
const Txn = types.Txn;
const TxnSigner = @import("signer/signer.zig").TxnSigner;
const httpz = @import("httpz");
const engine_api = @import("engine_api/engine_api.zig");
const json = std.json;

fn engineAPIHandler(req: *httpz.Request, res: *httpz.Response) !void {
    if (try req.json(engine_api.EngineAPIRequest)) |payload| {
        if (std.mem.eql(u8, payload.method, "engine_newPayloadV2")) {
            const execution_payload_json = payload.params[0];
            var execution_payload = try execution_payload_json.to_execution_payload(res.arena);
            try engine_api.execution_payload.newPayloadV2Handler(&execution_payload, res.arena);
        } else {
            res.status = 500;
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    std.log.info("Welcome to phant! 🐘", .{});
    const txn_signer = try TxnSigner.init(@intFromEnum(config.ChainId.Mainnet));

    // Create block.
    const block: Block = .{
        .header = .{
            .parent_hash = [_]u8{0} ** 32,
            .uncle_hash = [_]u8{0} ** 32,
            .fee_recipient = [_]u8{0} ** 20,
            .state_root = [_]u8{0} ** 32,
            .transactions_root = [_]u8{0} ** 32,
            .receipts_root = [_]u8{0} ** 32,
            .logs_bloom = [_]u8{0} ** 256,
            .prev_randao = [_]u8{0} ** 32,
            .block_number = 100,
            .gas_limit = 10_000,
            .gas_used = 0,
            .timestamp = 0,
            .extra_data = &[_]u8{},
            .nonce = [_]u8{0} ** 8,
            .base_fee_per_gas = 10,
            .withdrawals_root = null,
            .blob_gas_used = null,
            .excess_blob_gas = null,
            .difficulty = 0,
        },
        .transactions = &[_]Txn{},
        .uncles = &[_]types.BlockHeader{},
        .withdrawals = &[_]types.Withdrawal{},
    };

    // Create some dummy transaction.
    var txn = Txn.initLegacyTxn(0, 10, 0, [_]u8{0} ** 18 ++ [_]u8{ 0x41, 0x42 }, &[_]u8{}, 100_000);
    var privkey: ecdsa.PrivateKey = undefined;
    _ = try std.fmt.hexToBytes(&privkey, "45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8");
    const sig = try txn_signer.sign(allocator, txn, privkey);
    txn.setSignature(sig.v, sig.r, sig.s);

    // Create the corresponding AccountState for txn.to, in particular with relevant bytecode
    // so the transaction can be properly executed.
    const code = [_]u8{
        0x61, 0x41, 0x42, // PUSH2 0x4142
        0x31, // BALANCE
    };
    const sender_addr = try txn_signer.get_sender(allocator, txn);
    var account_state = try AccountState.init(allocator, sender_addr, 0, 1_000_000, &code);
    defer account_state.deinit();

    // Create the statedb, with the created account state.
    var account_states = [_]AccountState{account_state};
    var statedb = try StateDB.init(allocator, &account_states);

    // Create the VM with the initialized statedb
    var vm = VM.init(&statedb);

    // Execute block with txns.
    vm.run_block(allocator, txn_signer, block, &[_]Txn{txn}) catch |err| {
        std.log.err("error executing transaction: {}", .{err});
        return;
    };

    var engine_api_server = try httpz.Server().init(allocator, .{
        .port = 8551,
    });
    var router = engine_api_server.router();
    router.post("/", engineAPIHandler);
    std.log.info("Listening on 8551", .{});
    try engine_api_server.listen();
}

test "tests" {
    std.testing.log_level = .debug;

    // TODO: move to separate file for tests binary.
    _ = @import("exec-spec-tests/execspectests.zig");
    _ = @import("types/types.zig");
    _ = @import("blockchain/vm.zig");
    _ = @import("crypto/ecdsa.zig");
    _ = @import("engine_api/engine_api.zig");
}
