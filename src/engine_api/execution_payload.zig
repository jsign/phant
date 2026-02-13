const std = @import("std");
const types = @import("../types/types.zig");
const lib = @import("../lib.zig");
const version = @import("../version.zig");
const Blockchain = lib.blockchain.Blockchain;
const state = lib.state;
const Allocator = std.mem.Allocator;
const BlockHeader = types.BlockHeader;
const Withdrawal = types.Withdrawal;
const Tx = types.Tx;

pub const PayloadAttributes = struct {
    timestamp: u64,
    random: types.Hash32,
    suggested_fee_recipient: types.Hash32,
    withdrawals: []*types.Withdrawal,
    beacon_root: ?types.Hash32,
};

pub const StatelessPayloadStatusV1 = struct {
    status: []const u8,
    state_root: types.Hash32,
    receipt_root: types.Hash32,
    validator_error: ?[]const u8,
};

pub const ExecutionPayloadEnvelope = struct {
    execution_payload: *ExecutionPayload,
    block_value: *types.Hash32,
    blobs_bundle: *BlobsBundleV1,
    Requests: [][]const u8,
    override: bool,
    witness: []const u8,
};

pub const BlobAndProofV1 = struct {
    blob: []const u8,
    proof: []const u8,
};

pub const BlobsBundleV1 = struct {
    commitments: []types.Hash32,
    proofs: []types.Hash32,
    blobs: []types.Hash32,
};

pub const PayloadStatusV1 = struct {
    status: []const u8,
    witness: []const u8,
    latest_valid_hash: ?types.Hash32,
    validattion_error: ?[]const u8,
};

pub const TransitionConfigurationV1 = struct {
    terminal_total_difficulty: []const u8,
    terminal_block_hash: types.Hash32,
    terminal_block_number: u64,
};

const PayloadVersion = enum(u8) {
    PayloadV1 = 1,
    PayloadV2,
    PayloadV3,
};

pub const PayloadID = struct {
    const Self = @This();
    inner: [8]u8,

    pub fn version(pid: *Self) PayloadVersion {
        return @as(PayloadVersion, @enumFromInt(pid.inner[0]));
    }

    pub fn string(pid: *Self, out: []u8) !void {
        if (out.len != 16) {
            return error.InvalidOutputBufferSize;
        }
        _ = try std.fmt.bufPrint(out, "{x}", .{pid.inner});
    }

    pub fn is(pid: *Self, versions: []PayloadVersion) bool {
        for (versions) |v| {
            if (pid.version() == v) {
                return true;
            }
        }
        return false;
    }
};

pub const ForkChoiceResponse = struct {
    payload_status: PayloadStatusV1,
    payload_id: *PayloadID,
};

pub const ForkchoiceStateV1 = struct {
    head_block_hash: types.Hash32,
    safe_block_hash: types.Hash32,
    finalized_block_hash: types.Hash32,
};

pub const ExecutionPayload = struct {
    parentHash: types.Hash32,
    feeRecipient: types.Address,
    stateRoot: types.Hash32,
    receiptsRoot: types.Hash32,
    logsBloom: [256]u8,
    prevRandao: types.Hash32,
    blockNumber: u64,
    gasLimit: u64,
    gasUsed: u64,
    timestamp: u64,
    extraData: []const u8,
    baseFeePerGas: u256,
    blockHash: types.Hash32,
    transactions: []Tx,

    withdrawals: []types.Withdrawal,
    blobGasUsed: ?u64,
    excessBlobGas: ?u64,
    // executionWitness : ?types.ExecutionWitness,

    allocator: Allocator,

    pub fn toBlock(self: *const ExecutionPayload) !types.Block {
        var withdrawals = std.array_list.Managed(lib.mpt.KeyVal).init(self.allocator);
        defer withdrawals.deinit();
        for (self.withdrawals, 0..) |w, index| {
            var key = [_]u8{0} ** 32;
            std.mem.writeInt(usize, key[24..], index, .big);
            try withdrawals.append(try lib.mpt.KeyVal.init(self.allocator, &key, try w.encode(self.allocator)));
        }
        var transactions = std.array_list.Managed(lib.mpt.KeyVal).init(self.allocator);
        defer transactions.deinit();
        for (self.transactions, 0..) |tx, index| {
            var key = [_]u8{0} ** 32;
            std.mem.writeInt(usize, key[24..], index, .big);
            try transactions.append(try lib.mpt.KeyVal.init(self.allocator, &key, try tx.encode(self.allocator)));
        }
        return types.Block{
            .header = types.BlockHeader{
                .parent_hash = self.parentHash,
                .uncle_hash = types.empty_uncle_hash,
                .fee_recipient = self.feeRecipient,
                .state_root = self.stateRoot,
                .receipts_root = self.receiptsRoot,
                .logs_bloom = self.logsBloom,
                .difficulty = 0,
                .prev_randao = self.prevRandao,
                .block_number = @intCast(self.blockNumber),
                .gas_limit = @intCast(self.gasLimit),
                .gas_used = self.gasUsed,
                .timestamp = @intCast(self.timestamp),
                .extra_data = self.extraData,
                .base_fee_per_gas = self.baseFeePerGas,
                .transactions_root = try lib.mpt.mptize(self.allocator, transactions.items[0..]),
                .nonce = [_]u8{0} ** 8,
                .withdrawals_root = try lib.mpt.mptize(self.allocator, withdrawals.items[0..]),
                .blob_gas_used = self.blobGasUsed,
                .excess_blob_gas = self.excessBlobGas,
            },
            .transactions = self.transactions,
            .withdrawals = self.withdrawals,
            .uncles = &[0]BlockHeader{},
        };
    }

    pub fn deinit(self: *ExecutionPayload, allocator: std.mem.Allocator) void {
        if (self.extraData.len > 0) {
            allocator.free(self.extraData);
        }
    }
};

pub fn newPayloadV2Handler(blockchain: *Blockchain, params: *ExecutionPayload) !void {
    const block = try params.toBlock();
    // TODO reconstruct the proof from the (currently undefined) execution witness
    // and verify it.

    // Then execute the block and return the result.
    return blockchain.runBlock(block);
}

pub const ExecutionPayloadBody = struct {
    transaction_data: []types.Hash32,
    withdrawals: []*types.Withdrawal,
};

const client_code = "PH";
const client_name = "phant";

const ClientVersionV1 = struct {
    code: []const u8,
    name: []const u8,
    version: []const u8,
    commit: []const u8,

    // Allocates a buffer and write a string representing the version to
    // it. It is the responsibility of the caller to free the allocated
    // buffer.
    pub fn string(self: @This(), allocator: std.mem.Allocator) []u8 {
        return std.fmt.allocPrint(allocator, "{}-{}-{}-{}", .{ self.code, self.name, self.version, self.commit });
    }
};

pub fn getClientVersionV1Handler() !ClientVersionV1 {
    return .{
        .code = client_code,
        .name = client_name,
        .version = version.release,
        .commit = version.revision,
    };
}
