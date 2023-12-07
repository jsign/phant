const std = @import("std");
const Allocator = std.mem.Allocator;
const rlp = @import("zig-rlp");
const hasher = @import("../crypto/hasher.zig");
const types = @import("types.zig");
const Address = types.Address;
const Hash32 = types.Hash32;

pub const TxnTypes = enum(u4) {
    LegacyTxn = 0,
    // TODO
    //     AccessListTransaction,
    FeeMarketTxn = 2,
};

pub const Txn = union(TxnTypes) {
    LegacyTxn: LegacyTxn,
    FeeMarketTxn: FeeMarketTxn,
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

        // EIP-2718: Transaction Type Transaction
        if (bytes[0] <= 0x7f) {
            //     if (bytes[0] == 0x01) return AccessListTxn.decode(bytes[1...]);
            if (bytes[0] == 0x02) return Txn{ .FeeMarketTxn = try FeeMarketTxn.decode(bytes[1..]) };
            return error.UnsupportedEIP2930TxnType;
        }

        // LegacyTxn
        if (bytes[0] >= 0xc0 and bytes[0] <= 0xfe) return Txn{ .LegacyTxn = try LegacyTxn.decode(bytes) };

        return error.UnsupportedTxnType;
    }

    pub fn hash(self: Txn, allocator: Allocator) !Hash32 {
        return switch (self) {
            Txn.LegacyTxn => |txn| try txn.hash(allocator),
            Txn.FeeMarketTxn => |txn| try txn.hash(allocator),
        };
    }

    pub fn getChainId(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.chainIdFromSignature(),
            Txn.FeeMarketTxn => |txn| txn.chain_id,
        };
    }

    pub fn getGasPrice(self: Txn) u256 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.gas_price,
            Txn.FeeMarketTxn => |txn| txn.max_fee_per_gas,
        };
    }

    pub fn getNonce(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.nonce,
            Txn.FeeMarketTxn => |txn| txn.nonce,
        };
    }

    pub fn getData(self: Txn) []const u8 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.data,
            Txn.FeeMarketTxn => |txn| txn.data,
        };
    }

    pub fn getTo(self: Txn) ?Address {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.to,
            Txn.FeeMarketTxn => |txn| txn.to,
        };
    }

    pub fn getValue(self: Txn) u256 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.value,
            Txn.FeeMarketTxn => |txn| txn.value,
        };
    }

    pub fn getGasLimit(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.gas_limit,
            Txn.FeeMarketTxn => |txn| txn.gas,
        };
    }

    pub fn setSignature(self: *Txn, v: u256, r: u256, s: u256) void {
        switch (self.*) {
            Txn.LegacyTxn => |*txn| txn.setSignature(v, r, s),
            Txn.FeeMarketTxn => |*txn| txn.setSignature(v, r, s),
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
        return try RLPDecode(LegacyTxn, bytes);
    }

    pub fn hash(self: LegacyTxn, allocator: Allocator) !Hash32 {
        // TODO: consider caching the calculated txnHash to avoid further
        // allocations and keccaking. But be careful since struct fields are public.
        return try RLPHash(LegacyTxn, allocator, self, null);
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
    StorageKeys: []Hash32,
};

pub const AccessListTxn = struct {
    data: struct {
        chain_id: u64,
        nonce: u64,
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
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u64,
    max_fee_per_gas: u64,
    gas: u64,
    to: ?Address,
    value: u256,
    data: []const u8,
    access_list: []AccessListTuple,
    y_parity: u256,
    r: u256,
    s: u256,

    pub fn hash(self: FeeMarketTxn, allocator: Allocator) !Hash32 {
        // TODO: consider caching the calculated txnHash to avoid further
        // allocations and keccaking. But be careful since struct fields are public.
        const prefix = [_]u8{@intFromEnum(TxnTypes.FeeMarketTxn)};
        return try RLPHash(FeeMarketTxn, allocator, self, &prefix);
    }

    pub fn setSignature(self: *FeeMarketTxn, v: u256, r: u256, s: u256) void {
        self.*.y_parity = v;
        self.*.r = r;
        self.*.s = s;
    }

    // decode decodes a transaction from bytes. No bytes from the input slice are referenced in the
    // output transaction.
    pub fn decode(bytes: []const u8) !FeeMarketTxn {
        return try RLPDecode(FeeMarketTxn, bytes);
    }
};

pub fn RLPDecode(comptime T: type, bytes: []const u8) !T {
    var ret: T = std.mem.zeroes(T);
    _ = try rlp.deserialize(T, bytes, &ret);
    return ret;
}

pub fn RLPHash(comptime T: type, allocator: Allocator, txn: T, prefix: ?[]const u8) !Hash32 {
    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();
    try rlp.serialize(T, allocator, txn, &out);
    if (prefix) |pre| {
        return hasher.keccak256WithPrefix(pre, out.items);
    }
    return hasher.keccak256(out.items);
}

test "Transaction hashing" {
    const testCase = struct {
        rlp_encoded: []const u8,
        expected_hash: []const u8,
    };
    const txns = [_]testCase{
        .{
            // LegacyTxn (post EIP-155)
            // https://etherscan.io/tx/0x4debed4e6d4fdbc05c2f9198733b24f2f8b08452b6d3d70cb8f86bf0d3f7aa8c
            .rlp_encoded = "f870830ce12a8505767265bc83015f9094f8c911c68f6a6b912fe735bbd953c3379336cbf3880df3bcfddc7af5748026a0b9a3cc95c11c7374458f12ca10a7d43949b99b9e3437806c6de78855b1059683a01cd240e45f48cb94e7e9e40184cd72d09865a8a2ecae62f62d3cc343877d56ae",
            .expected_hash = "4debed4e6d4fdbc05c2f9198733b24f2f8b08452b6d3d70cb8f86bf0d3f7aa8c",
        },
        .{
            // FeeMarketTxn (EIP-1559)
            // https://etherscan.io/tx/0x8fe4006825c930e54e5c418a030cd57e90988eb627155aa366927afcfd2454ff
            .rlp_encoded = "02f8710183063c3880850e58157afa825ac29427c115f0d823973743a5046139806adce5e9cfd58789c1870632dbf680c080a0569a22a4edf94faf30d55725d8529b70c3f5a1ec896efc262951d20335bc9e31a058631545d6756a8c4450b74509f9cf08f131f259f9bae8304518e7a12f2940d3",
            .expected_hash = "8fe4006825c930e54e5c418a030cd57e90988eb627155aa366927afcfd2454ff",
        },
        // TODO: add test for AccessListTxn type.
    };

    inline for (txns) |test_txn| {
        var txn_bytes: [test_txn.rlp_encoded.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&txn_bytes, test_txn.rlp_encoded);

        const txn = try Txn.decode(&txn_bytes);
        const hash = try txn.hash(std.testing.allocator);
        try std.testing.expectEqualStrings(test_txn.expected_hash, &std.fmt.bytesToHex(hash, std.fmt.Case.lower));
    }
}
