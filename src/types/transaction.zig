const std = @import("std");
const Allocator = std.mem.Allocator;
const rlp = @import("zig-rlp");
const hasher = @import("../crypto/hasher.zig");
const types = @import("types.zig");
const Address = types.Address;
const Hash32 = types.Hash32;

pub const SignatureValues = struct { r: u256, s: u256, v: u256 };

pub const TxnTypes = enum {
    LegacyTxn,
    // TODO
    //     AccessListTransaction,
    //     FeeMarketTransaction,
};

pub const Txn = union(TxnTypes) {
    LegacyTxn: LegacyTxn,
    // AccessListTransaction: AccessListTxn,
    // FeeMarketTransaction: FeeMarketTxn,

    // init initializes a transaction without signature fields.
    // TODO(jsign): comment about data ownership.
    pub fn initLegacyTxn(chain_id: u64, nonce: u64, gas_price: u256, value: u256, to: ?Address, data: []const u8, gas_limit: u64) Txn {
        return Txn{ .LegacyTxn = LegacyTxn.init(chain_id, nonce, gas_price, value, to, data, gas_limit) };
    }

    pub fn getChainId(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.data.chain_id,
        };
    }

    pub fn getGasPrice(self: Txn) u256 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.data.gas_price,
        };
    }

    pub fn getNonce(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.data.nonce,
        };
    }

    pub fn getData(self: Txn) []const u8 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.data.data,
        };
    }

    pub fn getTo(self: Txn) ?Address {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.data.to,
        };
    }

    pub fn getValue(self: Txn) u256 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.data.value,
        };
    }

    pub fn getGasLimit(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.data.gas_limit,
        };
    }

    pub fn getSignature(self: Txn) SignatureValues {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.getSignature(),
        };
    }

    pub fn setSignature(self: *Txn, v: u256, r: u256, s: u256) void {
        switch (self.*) {
            Txn.LegacyTxn => |*txn| txn.setSignature(v, r, s),
        }
    }

    pub fn hash(self: Txn, allocator: Allocator) !Hash32 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.hash(allocator),
        };
    }
};

pub const LegacyTxn = struct {
    data: struct {
        type: u8,
        chain_id: u64,
        nonce: u64,
        gas_price: u256,
        value: u256,
        to: ?Address,
        data: []const u8,
        gas_limit: u64,
    },
    v: u256,
    r: u256,
    s: u256,

    pub fn init(chain_id: u64, nonce: u64, gas_price: u256, value: u256, to: ?Address, data: []const u8, gas_limit: u64) LegacyTxn {
        return LegacyTxn{
            .data = .{
                .type = 0,
                .chain_id = chain_id,
                .nonce = nonce,
                .gas_price = gas_price,
                .value = value,
                .to = to,
                .data = data,
                .gas_limit = gas_limit,
            },
            .v = 0,
            .r = 0,
            .s = 0,
        };
    }

    pub fn hash(self: LegacyTxn, allocator: Allocator) !Hash32 {
        var out = std.ArrayList(u8).init(allocator);
        defer out.deinit();

        try rlp.serialize(@TypeOf(self.data), allocator, self.data, &out);

        return hasher.keccak256(out.items);
    }

    pub fn getSignature(self: LegacyTxn) SignatureValues {
        return SignatureValues{ .r = self.r, .s = self.s, .v = self.v };
    }

    pub fn setSignature(self: *LegacyTxn, v: u256, r: u256, s: u256) void {
        self.*.v = v;
        self.*.r = r;
        self.*.s = s;
    }
};

pub const AccessListTuple = struct {
    address: Address,
    StorageKeys: []const Hash32,
};

pub const AccessListTxn = struct {
    data: struct {
        chain_id: u64,
        nonce: u256,
        gas_price: u256,
        gas: u64,
        to: ?Address,
        value: u256,
        data: []const u8,
        access_list: []AccessListTuple,
    },
    y_parity: u1,
    r: u256,
    s: u256,
};

pub const FeeMarketTxn = struct {
    data: struct {
        chain_id: u64,
        nonce: u256,
        max_priority_fee_per_gas: u64,
        max_fee_per_gas: u64,
        gas: u64,
        to: ?Address,
        value: u256,
        data: []const u8,
        access_list: []AccessListTuple,
    },
    y_parity: u1,
    r: u256,
    s: u256,
};

// TODO: tests for each transaction type from mainnet (RLP decoding without signatures + transaction hashing)
