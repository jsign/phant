const std = @import("std");
const lib = @import("lib.zig");
const ChainConfig = lib.config.ChainConfig;
const types = @import("types/types.zig");
const crypto = @import("crypto/crypto.zig");
const ecdsa = crypto.ecdsa;
const AccountState = @import("state/state.zig").AccountState;
const Address = types.Address;
const VM = @import("blockchain/vm.zig").VM;
const StateDB = @import("state/state.zig").StateDB;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Tx = types.Tx;
const TxSigner = @import("signer/signer.zig").TxSigner;
const Hash32 = types.Hash32;
const httpz = @import("httpz");
const engine_api = @import("engine_api/engine_api.zig");
const json = std.json;
const simargs = @import("simargs");
const version = @import("version.zig").version;
const Blockchain = lib.blockchain.Blockchain;
const Fork = lib.blockchain.Fork;

const supported_methods = .{
    "engine_forkchoiceUpdatedV1",
    "engine_forkchoiceUpdatedV2",
    "engine_forkchoiceUpdatedV3",
    "engine_forkchoiceUpdatedWithWitnessV1",
    "engine_forkchoiceUpdatedWithWitnessV2",
    "engine_forkchoiceUpdatedWithWitnessV3",
    "engine_exchangeTransitionConfigurationV1",
    "engine_getPayloadV1",
    "engine_getPayloadV2",
    "engine_getPayloadV3",
    "engine_getPayloadV4",
    "engine_getBlobsV1",
    "engine_newPayloadV1",
    "engine_newPayloadV2",
    "engine_newPayloadV3",
    "engine_newPayloadV4",
    "engine_newPayloadWithWitnessV1",
    "engine_newPayloadWithWitnessV2",
    "engine_newPayloadWithWitnessV3",
    "engine_newPayloadWithWitnessV4",
    "engine_executeStatelessPayloadV1",
    "engine_executeStatelessPayloadV2",
    "engine_executeStatelessPayloadV3",
    "engine_executeStatelessPayloadV4",
    "engine_getPayloadBodiesByHashV1",
    "engine_getPayloadBodiesByHashV2",
    "engine_getPayloadBodiesByRangeV1",
    "engine_getPayloadBodiesByRangeV2",
    "engine_getClientVersionV1",
};

fn engineAPIHandler(blockchain: *Blockchain, req: *httpz.Request, res: *httpz.Response) !void {
    if (try req.json(engine_api.EngineAPIRequest)) |payload| {
        if (std.mem.eql(u8, payload.method, "engine_newPayloadV2")) {
            const execution_payload_json = payload.params[0];
            var execution_payload = try execution_payload_json.to_execution_payload(res.arena);
            defer execution_payload.deinit(res.arena);
            try engine_api.execution_payload.newPayloadV2Handler(blockchain, &execution_payload);
            return;
        }

        if (std.mem.eql(u8, payload.method, "engine_getClientVersionV1")) {
            const ver = try engine_api.execution_payload.getClientVersionV1Handler();
            try res.json(ver, .{});
            return;
        }

        res.status = 500;
    }
}

var config: ChainConfig = undefined;

const PhantArgs = struct {
    engine_api_port: ?u16,
    network_id: lib.config.ChainId = .Mainnet,
    chainspec: ?[]const u8,

    pub const __shorts__ = .{
        .engine_api_port = .p,
    };

    pub const __messages__ = .{
        .engine_api_port = "Speficy the port to listen to for Engine API messages",
        .network_id = "Specify the chain id of the network",
        .chainspec = "Specify a custom chainspec JSON file",
    };
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // TODO print usage upon failure (requires upstream changes)
    // TODO generate version from build and add it here
    const opts = try simargs.parse(gpa.allocator(), PhantArgs, "", version);
    defer opts.deinit();

    const port: u16 = if (opts.args.engine_api_port == null) 8551 else opts.args.engine_api_port.?;

    // Get the chain config from 2 possible sources, by priority
    // 1. Specified chainspec file
    // 2. embedded config based on a chain id specified with `--network_id`. If no network
    // is specified then the default (mainnet) is chosen.
    if (opts.args.chainspec == null) {
        config = try ChainConfig.fromChainId(opts.args.network_id, gpa.allocator());
    } else {
        var file = try std.fs.cwd().openFile(opts.args.chainspec.?, .{});
        config = try ChainConfig.fromChainSpec(try file.readToEndAlloc(gpa.allocator(), try file.getEndPos()), gpa.allocator());
    }

    std.log.info("Welcome to phant! 🐘", .{});
    std.log.info("version: {s}", .{version});
    try config.dump(allocator);

    var statedb = try StateDB.init(allocator, &[0]AccountState{});
    defer statedb.deinit();
    const parent_header = BlockHeader{
        .parent_hash = [_]u8{0} ** 32,
        .uncle_hash = types.empty_uncle_hash,
        .fee_recipient = [_]u8{0} ** 20,
        .state_root = [_]u8{0} ** 32,
        .transactions_root = [_]u8{0} ** 32,
        .receipts_root = [_]u8{0} ** 32,
        .logs_bloom = [_]u8{0} ** 256,
        .difficulty = 0,
        .block_number = 0,
        .gas_limit = 0,
        .gas_used = 0,
        .timestamp = 0,
        .extra_data = &[_]u8{},
        .prev_randao = [_]u8{0} ** 32,
        .nonce = [_]u8{0} ** 8,
        .base_fee_per_gas = 0,
        .withdrawals_root = [_]u8{0} ** 32,
    };
    var blockchain = try Blockchain.init(allocator, config.chainId, &statedb, parent_header, try Fork.frontier.newFrontierFork(allocator));

    var engine_api_server = try httpz.Server(*Blockchain).init(allocator, .{
        .port = port,
    }, &blockchain);
    var router = engine_api_server.router();
    router.post("/", engineAPIHandler);
    std.log.info("Listening on {}", .{port});
    try engine_api_server.listen();
}
