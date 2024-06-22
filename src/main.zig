const std = @import("std");
const lib = @import("lib.zig");
const Config = lib.config.Config;
const types = @import("types/types.zig");
const crypto = @import("crypto/crypto.zig");
const ecdsa = crypto.ecdsa;
const AccountState = @import("state/state.zig").AccountState;
const Address = types.Address;
const VM = @import("blockchain/vm.zig").VM;
const StateDB = @import("state/state.zig").StateDB;
const Block = types.Block;
const Tx = types.Tx;
const TxSigner = @import("signer/signer.zig").TxSigner;
const httpz = @import("httpz");
const engine_api = @import("engine_api/engine_api.zig");
const json = std.json;
const simargs = @import("simargs");

fn engineAPIHandler(req: *httpz.Request, res: *httpz.Response) !void {
    if (try req.json(engine_api.EngineAPIRequest)) |payload| {
        if (std.mem.eql(u8, payload.method, "engine_newPayloadV2")) {
            const execution_payload_json = payload.params[0];
            var execution_payload = try execution_payload_json.to_execution_payload(res.arena);
            defer execution_payload.deinit(res.arena);
            try engine_api.execution_payload.newPayloadV2Handler(&execution_payload, res.arena);
        } else {
            res.status = 500;
        }
    }
}

var config: Config = undefined;

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
    const opts = try simargs.parse(gpa.allocator(), PhantArgs, "", null);
    defer opts.deinit();

    const port: u16 = if (opts.args.engine_api_port == null) 8551 else opts.args.engine_api_port.?;

    // Get the chain config from 2 possible sources, by priority
    // 1. Specified chainspec file
    // 2. embedded config based on a chain id specified with `--network_id`. If no network
    // is specified then the default (mainnet) is chosen.
    if (opts.args.chainspec == null) {
        config = try Config.fromChainId(opts.args.network_id, gpa.allocator());
    } else {
        var file = try std.fs.cwd().openFile(opts.args.chainspec.?, .{});
        config = try Config.fromChainSpec(try file.readToEndAlloc(gpa.allocator(), try file.getEndPos()), gpa.allocator());
    }

    std.log.info("Welcome to phant! 🐘", .{});
    try config.dump(allocator);

    var engine_api_server = try httpz.Server().init(allocator, .{
        .port = port,
    });
    var router = engine_api_server.router();
    router.post("/", engineAPIHandler);
    std.log.info("Listening on {}", .{port});
    try engine_api_server.listen();
}
