const std = @import("std");
const types = @import("types/types.zig");
const crypto = @import("crypto/crypto.zig");
const ecdsa = crypto.ecdsa;
const config = @import("config/config.zig");
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
const cli = @import("zig-cli");

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

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

var configuration = config.Config{};

var engine_port = cli.Option{
    .long_name = "engine-port",
    .help = "port of the execution engine",
    .value_ref = cli.mkRef(&configuration.engine_port),
};

var network_id_opt = cli.Option{
    .long_name = "network-id",
    .help = "network id",
    .value_ref = cli.mkRef(&configuration.network_id),
};

var app = &cli.App{
    .command = cli.Command{
        .name = "run",
        .options = &.{ &network_id_opt, &engine_port },
        .target = cli.CommandTarget{
            .action = cli.CommandAction{ .exec = run_server },
        },
    },
};

fn run_server() !void {
    var engine_api_server = try httpz.Server().init(allocator, .{
        .port = configuration.engine_port,
    });
    var router = engine_api_server.router();
    router.post("/", engineAPIHandler);
    std.log.info("Listening on port {}", .{configuration.engine_port});
    try engine_api_server.listen();
}

pub fn main() !void {
    std.log.info("Welcome to phant! 🐘", .{});

    return cli.run(app, allocator);
}
