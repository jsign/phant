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
    pub fn initLegacyTxn(nonce: u64, gas_price: u256, value: u256, to: ?Address, data: []const u8, gas_limit: u64) Txn {
        return Txn{ .LegacyTxn = LegacyTxn.init(nonce, gas_price, value, to, data, gas_limit) };
    }

    // decode decodes a transaction from bytes. The provided bytes are referenced in the returned transaction.
    pub fn decode(bytes: []const u8) !Txn {
        if (bytes.len == 0) {
            return error.EncodedTxnCannotBeEmpty;
        }

        // EIP-2930: Transaction Type Transaction
        // if (bytes[0] <= 0x7f) {
        //     if (bytes[0] == 0x01) return AccessListTxn.decode(bytes);
        //     if (bytes[0] == 0x02) return FeeMarketTxn.decode(bytes);
        //     return error.UnsupportedEIP2930TxnType;
        // }

        // LegacyTxn
        if (bytes[0] >= 0xc0 and bytes[0] <= 0xfe) return Txn{ .LegacyTxn = try LegacyTxn.decode(bytes) };

        return error.UnsupportedTxnType;
    }

    pub fn txnHash(self: Txn) Hash32 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.LegacyTxn.txnHash(),
        };
    }

    pub fn getChainId(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.chainIdFromSignature(),
        };
    }

    pub fn getGasPrice(self: Txn) u256 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.gas_price,
        };
    }

    pub fn getNonce(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.nonce,
        };
    }

    pub fn getData(self: Txn) []const u8 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.data,
        };
    }

    pub fn getTo(self: Txn) ?Address {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.to,
        };
    }

    pub fn getValue(self: Txn) u256 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.value,
        };
    }

    pub fn hash(self: Txn, allocator: Allocator) !Hash32 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.hash(allocator),
        };
    }

    pub fn getGasLimit(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.gas_limit,
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
};

pub const LegacyTxn = struct {
    nonce: u64,
    gas_price: u256,
    gas_limit: u64,
    to: ?Address,
    value: u256,
    data: []const u8,
    v: u256,
    r: u256,
    s: u256,

    pub fn init(nonce: u64, gas_price: u256, value: u256, to: ?Address, data: []const u8, gas_limit: u64) LegacyTxn {
        return LegacyTxn{
            .nonce = nonce,
            .gas_price = gas_price,
            .value = value,
            .to = to,
            .data = data,
            .gas_limit = gas_limit,
            .v = 0,
            .r = 0,
            .s = 0,
        };
    }

    // decode decodes a transaction from bytes. No bytes from the input slice are referenced in the
    // output transaction.
    pub fn decode(bytes: []const u8) !LegacyTxn {
        var txn: LegacyTxn = undefined;
        _ = try rlp.deserialize(LegacyTxn, bytes, &txn);
        return txn;
    }

    pub fn hash(self: LegacyTxn, allocator: Allocator) !Hash32 {
        // TODO: consider caching the calculated txnHash to avoid further
        // allocations and keccaking. But be careful since struct fields are public.
        var out = std.ArrayList(u8).init(allocator);
        defer out.deinit();
        try rlp.serialize(LegacyTxn, allocator, self, &out);
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

    pub fn chainIdFromSignature(self: LegacyTxn) u64 {
        // In legacy signatures, the chain id is assumed to be zero.
        if (self.v == 27 or self.v == 28) {
            return 0;
        }
        // Since EIP-155, it's encoded in v.
        return @intCast((self.v - 35) >> 1);
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

test "LegacyTxn (post EIP-155) hashing" {
    // Pulled from mainnet:
    // https://etherscan.io/getRawTx?tx=0x4debed4e6d4fdbc05c2f9198733b24f2f8b08452b6d3d70cb8f86bf0d3f7aa8c
    const legacy_txn_hex = "f870830ce12a8505767265bc83015f9094f8c911c68f6a6b912fe735bbd953c3379336cbf3880df3bcfddc7af5748026a0b9a3cc95c11c7374458f12ca10a7d43949b99b9e3437806c6de78855b1059683a01cd240e45f48cb94e7e9e40184cd72d09865a8a2ecae62f62d3cc343877d56ae";
    var legacy_txn_bytes: [legacy_txn_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&legacy_txn_bytes, legacy_txn_hex);

    const legacy_txn = try Txn.decode(&legacy_txn_bytes);
    const hash = try legacy_txn.LegacyTxn.hash(std.testing.allocator);
    try std.testing.expectEqualStrings(
        "4debed4e6d4fdbc05c2f9198733b24f2f8b08452b6d3d70cb8f86bf0d3f7aa8c",
        &std.fmt.bytesToHex(hash, std.fmt.Case.lower),
    );
}

// TODO: same tests for FeeMarketTxn and AccessListTxn
