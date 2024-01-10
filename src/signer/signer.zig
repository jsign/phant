const std = @import("std");
const Allocator = std.mem.Allocator;
const config = @import("../config/config.zig");
const ecdsa = @import("../crypto/ecdsa.zig");
const types = @import("../types/types.zig");
const rlp = @import("zig-rlp");
const hasher = @import("../crypto/hasher.zig");
const AccessListTuple = types.AccessListTuple;
const Txn = types.Txn;
const Hash32 = types.Hash32;
const Address = @import("../types/types.zig").Address;

// TODO: TxnSigner should be generalized to:
// - Only accept correct transactions types depending on the fork we're in.
pub const TxnSigner = struct {
    chain_id: u64,
    ecdsa_signer: ecdsa.Signer,

    pub fn init(chain_id: u64) !TxnSigner {
        return TxnSigner{
            .chain_id = chain_id,
            .ecdsa_signer = try ecdsa.Signer.init(),
        };
    }

    pub fn sign(self: TxnSigner, allocator: Allocator, txn: Txn, privkey: ecdsa.PrivateKey) !struct { r: u256, s: u256, v: u256 } {
        const txn_hash = try self.hashTxn(allocator, txn);

        const ecdsa_sig = try self.ecdsa_signer.sign(txn_hash, privkey);
        const r = std.mem.readIntSlice(u256, ecdsa_sig[0..32], std.builtin.Endian.Big);
        const s = std.mem.readIntSlice(u256, ecdsa_sig[32..64], std.builtin.Endian.Big);
        const v = switch (txn) {
            Txn.LegacyTxn => 35 + 2 * self.chain_id, // We sign using EIP155 since 2016.
            Txn.AccessListTxn, Txn.FeeMarketTxn => 0,
        } + ecdsa_sig[64];
        return .{ .r = r, .s = s, .v = v };
    }

    pub fn get_sender(self: TxnSigner, allocator: Allocator, tx: Txn) !Address {
        const txn_hash = try self.hashTxn(allocator, tx);

        var sig: ecdsa.Signature = undefined;

        // TODO: solve malleability problem.
        sig[64] = switch (tx) {
            Txn.LegacyTxn => |txn| blk: {
                std.mem.writeIntSlice(u256, sig[0..32], txn.r, std.builtin.Endian.Big);
                std.mem.writeIntSlice(u256, sig[32..64], txn.s, std.builtin.Endian.Big);

                if (txn.v == 27 or txn.v == 28) {
                    break :blk @intCast(txn.v - 27);
                }
                const v_eip155 = 35 + 2 * self.chain_id;
                if (txn.v != v_eip155 and txn.v != v_eip155 + 1) {
                    return error.EIP155_v;
                }
                break :blk @intCast(txn.v - v_eip155);
            },
            Txn.AccessListTxn => |txn| blk: {
                std.mem.writeIntSlice(u256, sig[0..32], txn.r, std.builtin.Endian.Big);
                std.mem.writeIntSlice(u256, sig[32..64], txn.s, std.builtin.Endian.Big);
                break :blk @intCast(txn.y_parity);
            },
            Txn.FeeMarketTxn => |txn| blk: {
                std.mem.writeIntSlice(u256, sig[0..32], txn.r, std.builtin.Endian.Big);
                std.mem.writeIntSlice(u256, sig[32..64], txn.s, std.builtin.Endian.Big);
                break :blk @intCast(txn.y_parity);
            },
        };

        const pubkey = try self.ecdsa_signer.erecover(sig, txn_hash);
        return hasher.keccak256(pubkey[1..])[12..].*;
    }

    fn hashTxn(self: TxnSigner, allocator: Allocator, transaction: Txn) !Hash32 {
        return switch (transaction) {
            Txn.LegacyTxn => |txn| blk: {
                var out = std.ArrayList(u8).init(allocator);
                defer out.deinit();

                if (self.chain_id != @intFromEnum(config.ChainId.SpecTest)) {
                    // Post EIP-155 (since ~Nov 2016).
                    const legacyTxnRLP = struct {
                        nonce: u64,
                        gas_price: u256,
                        gas_limit: u64,
                        to: ?Address,
                        value: u256,
                        data: []const u8,
                        chain_id: u64,
                        zero1: u8 = 0,
                        zero2: u8 = 0,
                    };

                    try rlp.serialize(legacyTxnRLP, allocator, .{
                        .nonce = txn.nonce,
                        .gas_price = txn.gas_price,
                        .gas_limit = txn.gas_limit,
                        .to = txn.to,
                        .value = txn.value,
                        .data = txn.data,
                        .chain_id = self.chain_id,
                    }, &out);
                } else {
                    // Pre EIP-155.
                    const legacyTxnRLP = struct {
                        nonce: u64,
                        gas_price: u256,
                        gas_limit: u64,
                        to: ?Address,
                        value: u256,
                        data: []const u8,
                    };

                    try rlp.serialize(legacyTxnRLP, allocator, .{
                        .nonce = txn.nonce,
                        .gas_price = txn.gas_price,
                        .gas_limit = txn.gas_limit,
                        .to = txn.to,
                        .value = txn.value,
                        .data = txn.data,
                    }, &out);
                }

                break :blk hasher.keccak256(out.items);
            },
            Txn.FeeMarketTxn => |txn| blk: {
                const feeMarketRLP = struct {
                    chain_id: u64,
                    nonce: u256,
                    max_priority_fee_per_gas: u64,
                    max_fee_per_gas: u256,
                    gas: u64,
                    to: ?Address,
                    value: u256,
                    data: []const u8,
                    access_list: []AccessListTuple,
                };

                var out = std.ArrayList(u8).init(allocator);
                defer out.deinit();
                try rlp.serialize(feeMarketRLP, allocator, .{
                    .chain_id = txn.chain_id,
                    .nonce = txn.nonce,
                    .max_priority_fee_per_gas = txn.max_priority_fee_per_gas,
                    .max_fee_per_gas = txn.max_fee_per_gas,
                    .gas = txn.gas,
                    .to = txn.to,
                    .value = txn.value,
                    .data = txn.data,
                    .access_list = txn.access_list,
                }, &out);
                break :blk hasher.keccak256WithPrefix(&[_]u8{@intFromEnum(Txn.FeeMarketTxn)}, out.items);
            },
            Txn.AccessListTxn => |txn| blk: {
                const accessListRLP = struct {
                    chain_id: u64,
                    nonce: u64,
                    gas_price: u256,
                    gas: u64,
                    to: ?Address,
                    value: u256,
                    data: []const u8,
                    access_list: []AccessListTuple,
                };

                var out = std.ArrayList(u8).init(allocator);
                defer out.deinit();
                try rlp.serialize(accessListRLP, allocator, .{
                    .chain_id = txn.chain_id,
                    .nonce = txn.nonce,
                    .gas_price = txn.gas_price,
                    .gas = txn.gas,
                    .to = txn.to,
                    .value = txn.value,
                    .data = txn.data,
                    .access_list = txn.access_list,
                }, &out);
                break :blk hasher.keccak256WithPrefix(&[_]u8{@intFromEnum(Txn.AccessListTxn)}, out.items);
            },
        };
    }
};

test "mainnet transactions signature recovery/verification" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const testCase = struct {
        rlp_encoded: []const u8,
        expected_sender: []const u8,
    };
    const test_cases = [_]testCase{
        .{
            // LegacyTxn (post EIP-155)
            // https://etherscan.io/tx/0x4debed4e6d4fdbc05c2f9198733b24f2f8b08452b6d3d70cb8f86bf0d3f7aa8c
            .rlp_encoded = "f870830ce12a8505767265bc83015f9094f8c911c68f6a6b912fe735bbd953c3379336cbf3880df3bcfddc7af5748026a0b9a3cc95c11c7374458f12ca10a7d43949b99b9e3437806c6de78855b1059683a01cd240e45f48cb94e7e9e40184cd72d09865a8a2ecae62f62d3cc343877d56ae",
            .expected_sender = "ea674fdde714fd979de3edf0f56aa9716b898ec8",
        },
        .{
            // FeeMarketTxn (EIP-1559)
            // https://etherscan.io/tx/0x8fe4006825c930e54e5c418a030cd57e90988eb627155aa366927afcfd2454ff
            .rlp_encoded = "02f8710183063c3880850e58157afa825ac29427c115f0d823973743a5046139806adce5e9cfd58789c1870632dbf680c080a0569a22a4edf94faf30d55725d8529b70c3f5a1ec896efc262951d20335bc9e31a058631545d6756a8c4450b74509f9cf08f131f259f9bae8304518e7a12f2940d3",
            .expected_sender = "1f9090aae28b8a3dceadf281b0f12828e676c326",
        },
    };

    inline for (test_cases) |testcase| {
        var txn_bytes: [testcase.rlp_encoded.len / 2]u8 = undefined;
        _ = try std.fmt.hexToBytes(&txn_bytes, testcase.rlp_encoded);
        const txn = try Txn.decode(arena.allocator(), &txn_bytes);

        const signer = try TxnSigner.init(@intFromEnum(config.ChainId.Mainnet));
        const sender = try signer.get_sender(std.testing.allocator, txn);

        try std.testing.expectEqualStrings(
            testcase.expected_sender,
            &std.fmt.bytesToHex(sender, std.fmt.Case.lower),
        );
    }
}
