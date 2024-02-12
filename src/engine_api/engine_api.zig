const std = @import("std");
const fmt = std.fmt;
const types = @import("../types/types.zig");
const common = @import("../common/common.zig");
const Allocator = std.mem.Allocator;
const Withdrawal = types.Withdrawal;
const Tx = types.Tx;
const ExecutionPayload = execution_payload.ExecutionPayload;

pub const execution_payload = @import("execution_payload.zig");

// This is an intermediate structure used to deserialize the hex strings
// from the JSON request. I have seen some zig libraries that can do this
// out of the box, but it seems that approach hasn't been merged into the
// std yet.
// Because the JSON libary won't be able to deserialize a union unless
// the union is explicitly named, all possible object keys are declared in
// this object, and the caller is responsible for sifting through them by
// calling any of the `to_*` method, based on the context.
const AllPossibleExecutionParams = struct {
    parentHash: []const u8,
    feeRecipient: []const u8,
    stateRoot: []const u8,
    receiptsRoot: []const u8,
    logsBloom: []const u8,
    prevRandao: []const u8,
    blockNumber: []const u8,
    gasLimit: []const u8,
    gasUsed: []const u8,
    timestamp: []const u8,
    extraData: []const u8,
    baseFeePerGas: []const u8,
    blockHash: []const u8,
    transactions: [][]const u8,

    pub fn to_execution_payload(self: *const AllPossibleExecutionParams, allocator: Allocator) !ExecutionPayload {
        var txs: []Tx = &[0]Tx{};
        if (self.transactions.len > 0) {
            txs = try allocator.alloc(Tx, self.transactions.len);
            for (self.transactions, 0..) |tx, i| {
                txs[i] = try Tx.decode(allocator, tx);
            }
        }

        var ret = ExecutionPayload{
            .parentHash = undefined,
            .feeRecipient = undefined,
            .stateRoot = undefined,
            .receiptsRoot = undefined,
            .prevRandao = undefined,
            .extraData = try common.prefixedhex2byteslice(allocator, self.extraData),
            .blockHash = undefined,
            .logsBloom = undefined,
            .blockNumber = try common.prefixedhex2u64(self.blockNumber),
            .gasLimit = try common.prefixedhex2u64(self.gasLimit),
            .gasUsed = try common.prefixedhex2u64(self.gasUsed),
            .timestamp = try common.prefixedhex2u64(self.timestamp),
            .baseFeePerGas = try common.prefixedhex2u64(self.baseFeePerGas),
            .transactions = txs,
            .withdrawals = &[0]Withdrawal{},
            .blobGasUsed = null,
            .excessBlobGas = null,
            .allocator = allocator,
        };

        _ = try common.prefixedhex2hash(ret.parentHash[0..], self.parentHash);
        _ = try common.prefixedhex2hash(ret.feeRecipient[0..], self.feeRecipient);
        _ = try common.prefixedhex2hash(ret.stateRoot[0..], self.stateRoot);
        _ = try common.prefixedhex2hash(ret.receiptsRoot[0..], self.receiptsRoot);
        _ = try common.prefixedhex2hash(ret.logsBloom[0..], self.logsBloom);
        _ = try common.prefixedhex2hash(ret.prevRandao[0..], self.prevRandao);
        _ = try common.prefixedhex2hash(ret.blockHash[0..], self.blockHash);

        return ret;
    }
};

pub const EngineAPIRequest = struct {
    jsonrpc: []const u8,
    id: u64,
    method: []const u8,
    params: []const AllPossibleExecutionParams,
};

test "deserialize sample engine_newPayloadV2" {
    const json = std.json;
    const expect = std.testing.expect;

    const fileContent = @embedFile("./test_req.json");

    const payload = try json.parseFromSlice(EngineAPIRequest, std.testing.allocator, fileContent, .{ .ignore_unknown_fields = true });
    defer payload.deinit();

    try expect(std.mem.eql(u8, payload.value.method, "engine_newPayloadV2"));
    const execution_payload_json = payload.value.params[0];
    var ep = try execution_payload_json.to_execution_payload(std.testing.allocator);
    try execution_payload.newPayloadV2Handler(&ep, std.testing.allocator);
}
