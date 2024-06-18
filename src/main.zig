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
    const allocator = gpa.allocator();

    std.log.info("Welcome to phant! 🐘", .{});

    var engine_api_server = try httpz.Server().init(allocator, .{
        .port = 8551,
    });
    var router = engine_api_server.router();
    router.post("/", engineAPIHandler);
    std.log.info("Listening on 8551", .{});
    try engine_api_server.listen();
}
