const std = @import("std");
const Allocator = std.mem.Allocator;
const rlp = @import("zig-rlp");
const hasher = @import("../crypto/hasher.zig");
const types = @import("types.zig");
const Address = types.Address;
const Hash32 = types.Hash32;

pub const TxnTypes = enum(u4) {
    LegacyTxn = 0,
    AccessListTxn = 1,
    FeeMarketTxn = 2,
};

pub const Txn = union(TxnTypes) {
    LegacyTxn: LegacyTxn,
    AccessListTxn: AccessListTxn,
    FeeMarketTxn: FeeMarketTxn,

    // init initializes a transaction without signature fields.
    // TODO(jsign): comment about data ownership.
    pub fn initLegacyTxn(nonce: u64, gas_price: u256, value: u256, to: ?Address, data: []const u8, gas_limit: u64) Txn {
        return Txn{ .LegacyTxn = LegacyTxn.init(nonce, gas_price, value, to, data, gas_limit) };
    }

    // decode decodes a transaction from bytes. The provided bytes are referenced in the returned transaction.
    pub fn decode(arena: Allocator, bytes: []const u8) !Txn {
        if (bytes.len == 0) {
            return error.EncodedTxnCannotBeEmpty;
        }

        // EIP-2718: Transaction Type Transaction
        if (bytes[0] <= 0x7f) {
            if (bytes[0] == 0x01) return Txn{ .AccessListTxn = try AccessListTxn.decode(arena, bytes[1..]) };
            if (bytes[0] == 0x02) return Txn{ .FeeMarketTxn = try FeeMarketTxn.decode(arena, bytes[1..]) };
            return error.UnsupportedEIP2930TxnType;
        }

        // LegacyTxn
        if (bytes[0] >= 0xc0 and bytes[0] <= 0xfe) return Txn{ .LegacyTxn = try LegacyTxn.decode(arena, bytes) };

        return error.UnsupportedTxnType;
    }

    pub fn hash(self: Txn, allocator: Allocator) !Hash32 {
        return switch (self) {
            Txn.LegacyTxn => |txn| try txn.hash(allocator),
            Txn.AccessListTxn => |txn| try txn.hash(allocator),
            Txn.FeeMarketTxn => |txn| try txn.hash(allocator),
        };
    }

    pub fn getChainId(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.chainIdFromSignature(),
            Txn.AccessListTxn => |txn| txn.chain_id,
            Txn.FeeMarketTxn => |txn| txn.chain_id,
        };
    }

    pub fn getGasPrice(self: Txn) u256 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.gas_price,
            Txn.AccessListTxn => |txn| txn.gas_price,
            Txn.FeeMarketTxn => |txn| txn.max_fee_per_gas,
        };
    }

    pub fn getNonce(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.nonce,
            Txn.AccessListTxn => |txn| txn.nonce,
            Txn.FeeMarketTxn => |txn| txn.nonce,
        };
    }

    pub fn getData(self: Txn) []const u8 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.data,
            Txn.AccessListTxn => |txn| txn.data,
            Txn.FeeMarketTxn => |txn| txn.data,
        };
    }

    pub fn getTo(self: Txn) ?Address {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.to,
            Txn.AccessListTxn => |txn| txn.to,
            Txn.FeeMarketTxn => |txn| txn.to,
        };
    }

    pub fn getValue(self: Txn) u256 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.value,
            Txn.AccessListTxn => |txn| txn.value,
            Txn.FeeMarketTxn => |txn| txn.value,
        };
    }

    pub fn getGasLimit(self: Txn) u64 {
        return switch (self) {
            Txn.LegacyTxn => |txn| txn.gas_limit,
            Txn.AccessListTxn => |txn| txn.gas,
            Txn.FeeMarketTxn => |txn| txn.gas,
        };
    }

    pub fn setSignature(self: *Txn, v: u256, r: u256, s: u256) void {
        switch (self.*) {
            Txn.LegacyTxn => |*txn| txn.setSignature(v, r, s),
            Txn.AccessListTxn => |*txn| txn.setSignature(v, r, s),
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
    pub fn decode(arena: Allocator, bytes: []const u8) !LegacyTxn {
        return try RLPDecode(LegacyTxn, arena, bytes);
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
    storage_keys: []Hash32,
};

pub const AccessListTxn = struct {
    chain_id: u64,
    nonce: u64,
    gas_price: u256,
    gas: u64,
    to: ?Address,
    value: u256,
    data: []const u8,
    access_list: []AccessListTuple,
    y_parity: u256,
    r: u256,
    s: u256,

    pub fn hash(self: AccessListTxn, allocator: Allocator) !Hash32 {
        // TODO: consider caching the calculated txnHash to avoid further
        // allocations and keccaking. But be careful since struct fields are public.
        const prefix = [_]u8{@intFromEnum(TxnTypes.AccessListTxn)};
        return try RLPHash(AccessListTxn, allocator, self, &prefix);
    }

    pub fn setSignature(self: *AccessListTxn, v: u256, r: u256, s: u256) void {
        self.*.y_parity = v;
        self.*.r = r;
        self.*.s = s;
    }

    // decode decodes a transaction from bytes.
    pub fn decode(arena: Allocator, bytes: []const u8) !AccessListTxn {
        return try RLPDecode(AccessListTxn, arena, bytes);
    }
};

pub const FeeMarketTxn = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u64,
    max_fee_per_gas: u256,
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

    // decode decodes a transaction from bytes.
    pub fn decode(arena: Allocator, bytes: []const u8) !FeeMarketTxn {
        return try RLPDecode(FeeMarketTxn, arena, bytes);
    }
};

pub fn RLPDecode(comptime T: type, arena: Allocator, bytes: []const u8) !T {
    var ret: T = std.mem.zeroes(T);
    _ = try rlp.deserialize(T, bytes, &ret, arena);
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

test "Mainnet transactions hashing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const testCase = struct {
        rlp_encoded: []const u8,
        expected_hash: []const u8,
    };
    const test_cases = [_]testCase{
        .{
            // LegacyTxn (post EIP-155)
            // https://etherscan.io/tx/0x4debed4e6d4fdbc05c2f9198733b24f2f8b08452b6d3d70cb8f86bf0d3f7aa8c
            .rlp_encoded = "f870830ce12a8505767265bc83015f9094f8c911c68f6a6b912fe735bbd953c3379336cbf3880df3bcfddc7af5748026a0b9a3cc95c11c7374458f12ca10a7d43949b99b9e3437806c6de78855b1059683a01cd240e45f48cb94e7e9e40184cd72d09865a8a2ecae62f62d3cc343877d56ae",
            .expected_hash = "4debed4e6d4fdbc05c2f9198733b24f2f8b08452b6d3d70cb8f86bf0d3f7aa8c",
        },
        // TODO: this test has been commented since there's a limitation in zig-rlp
        //       where it can't deserialize correctly non-empty lists of complex types.
        //       Whenever this is fixed, this test should be uncommented and it should work.
        // .{
        //     // AccessListTxn (EIP-2930)
        //     // https://etherscan.io/tx/0x2f54a74664029c3f68d8681f45b3c66baf24fb9513f5111c5ec1fafbc9dc5491
        //     .rlp_encoded = "01f902e30182cd2f8559afb58c0083046100944a137fd5e7a256ef08a7de531a17d0be0cc7b6b680b901446dbf2fa000000000000000000000000049ff149d649769033d43783e7456f626862cd1600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a48201aa3f000000000000000000000000514910771af9ca656af840dff83e8264ecf986ca000000000000000000000000000000000000000000000017568b85db3ea800000000000000000000000000002260fac5e5542a773aa44fbcfedf7c193bc2c59900000000000000000000000000000000000000000000000000000000022030cbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000f90132f859942260fac5e5542a773aa44fbcfedf7c193bc2c599f842a014d5312942240e565c56aec11806ce58e3c0e38c96269d759c5d35a2a2e4a449a044fd617ddb9e84c66e959bd7f87ab8d484fe309ea10d899942502dfd33d9a007f8599449ff149d649769033d43783e7456f626862cd160f842a00f96d37f060a4c4d24b5db5a43f3ef48b5939bb9eee99c945607ea1d4c0038c6a0c8b0053af66e34563eef51d9e903539c0b7f677d87f2259d706bf5e6ced8dafdf87a94514910771af9ca656af840dff83e8264ecf986caf863a048a8b08c87098a2a36fb2cd5bfc8220e975243c2757604fe4d84d2bd8c63eed4a095cc1485fd874d10ef90527beafa703663fdb72c2f7e5516591b708b6345392ea0c8ea3e0ef45c92485f9d08079e77f52b915d460261f53a0598daf439d8fe5c7f01a0c13a61de90057d60daad7eb7fba8fc059e010c183673357f0c6df477d4ccf00fa02b33e1ab4aad236472706ae98cc11b5754d1d250f5ac04f9b0e15a2e6f9870ca",
        //     .expected_hash = "2f54a74664029c3f68d8681f45b3c66baf24fb9513f5111c5ec1fafbc9dc5491",
        // },
        .{
            // FeeMarketTxn (EIP-1559)
            // https://etherscan.io/tx/0x8fe4006825c930e54e5c418a030cd57e90988eb627155aa366927afcfd2454ff
            .rlp_encoded = "02f8710183063c3880850e58157afa825ac29427c115f0d823973743a5046139806adce5e9cfd58789c1870632dbf680c080a0569a22a4edf94faf30d55725d8529b70c3f5a1ec896efc262951d20335bc9e31a058631545d6756a8c4450b74509f9cf08f131f259f9bae8304518e7a12f2940d3",
            .expected_hash = "8fe4006825c930e54e5c418a030cd57e90988eb627155aa366927afcfd2454ff",
        },
    };

    inline for (test_cases) |testcase| {
        var txn_bytes: [testcase.rlp_encoded.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&txn_bytes, testcase.rlp_encoded);

        const txn = try Txn.decode(arena.allocator(), &txn_bytes);
        const hash = try txn.hash(std.testing.allocator);
        try std.testing.expectEqualStrings(testcase.expected_hash, &std.fmt.bytesToHex(hash, std.fmt.Case.lower));
    }
}
