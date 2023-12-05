const std = @import("std");
const Allocator = std.mem.Allocator;
const ecdsa = @import("../crypto/ecdsa.zig");
const Transaction = @import("../types/transaction.zig");
const Address = @import("../types/types.zig").Address;
const hasher = @import("../crypto/hasher.zig");

// TODO: TxnSigner should be generalized to:
// - Only accept correct transactions types depending on the fork we're in.
// - Handle "v" correctly depending on transaction type.
// For now it's a post London signer, and only support 1559 txns.
pub const TxnSigner = struct {
    ecdsa_signer: ecdsa.Signer,

    pub fn init() !TxnSigner {
        return TxnSigner{
            .ecdsa_signer = try ecdsa.Signer.init(),
        };
    }

    pub fn sign(self: TxnSigner, allocator: Allocator, txn: Transaction, privkey: ecdsa.PrivateKey) !struct { r: u256, s: u256, v: u8 } {
        const txn_hash = try txn.hash(allocator);

        const ecdsa_sig = try self.ecdsa_signer.sign(txn_hash, privkey);
        const r = std.mem.readIntSlice(u256, ecdsa_sig[0..32], std.builtin.Endian.Big);
        const s = std.mem.readIntSlice(u256, ecdsa_sig[32..64], std.builtin.Endian.Big);
        const v = ecdsa_sig[64];
        return .{ .r = r, .s = s, .v = v };
    }

    pub fn get_sender(self: TxnSigner, allocator: Allocator, txn: Transaction) !Address {
        const txn_hash = try txn.hash(allocator);
        var sig: ecdsa.Signature = undefined;
        std.mem.writeIntSlice(u256, sig[0..32], txn.r, std.builtin.Endian.Big);
        std.mem.writeIntSlice(u256, sig[32..64], txn.s, std.builtin.Endian.Big);
        sig[64] = txn.v;
        const pubkey = try self.ecdsa_signer.erecover(sig, txn_hash);
        return hasher.keccak256(pubkey[1..])[12..].*;
    }
};
