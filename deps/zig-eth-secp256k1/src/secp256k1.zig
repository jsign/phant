// Copyright 2015 Jeffrey Wilcke, Felix Lange, Gustav Simonsson. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be found in
// the LICENSE file.

// This file is a port of go-ethereum/crypto/secp256k1/secp256k1.go with some slight modifications.

const std = @import("std");
const secp256k1lib = @import("dcimport.zig");
pub const PrivateKey = [32]u8;
pub const PublicKey = [65]u8;
pub const Signature = [65]u8;
pub const Message = [32]u8;

pub const Secp256k1 = struct {
    pub const order: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    context: *secp256k1lib.secp256k1_context,

    pub fn init() !Secp256k1 {
        const context = secp256k1lib.secp256k1_context_create_sign_verify() orelse return error.FailedInitialize;
        return Secp256k1{
            .context = context,
        };
    }

    pub fn generate_keypair(self: Secp256k1) !struct { pubkey: PublicKey, privkey: PrivateKey } {
        const privkey = std.crypto.ecc.Secp256k1.scalar.random(std.builtin.Endian.big);
        var ecpubkey: secp256k1lib.secp256k1_pubkey = undefined;
        if (secp256k1lib.secp256k1_ec_pubkey_create(self.context, &ecpubkey, &privkey) == 0) {
            return error.ErrCalculatingPubkeyFromPrivkey;
        }
        var pubkey: PublicKey = undefined;
        var pubkey_length = pubkey.len;
        pubkey[0] = 4;
        if (secp256k1lib.secp256k1_ec_pubkey_serialize(self.context, pubkey[0..].ptr, &pubkey_length, &ecpubkey, secp256k1lib.SECP256K1_EC_UNCOMPRESSED) == 0) {
            return error.ErrMarshalingPubkey;
        }

        return .{
            .pubkey = pubkey,
            .privkey = privkey,
        };
    }

    pub fn sign(self: Secp256k1, msg: Message, key: PrivateKey) !Signature {
        if (secp256k1lib.secp256k1_ec_seckey_verify(self.context, &key) != 1) {
            return error.ErrorInvalidKey;
        }

        const noncefunc = secp256k1lib.secp256k1_nonce_function_rfc6979;
        var sigstruct: secp256k1lib.secp256k1_ecdsa_recoverable_signature = undefined;
        if (secp256k1lib.secp256k1_ecdsa_sign_recoverable(self.context, &sigstruct, &msg, &key, noncefunc, null) == 0) {
            return error.ErrorSignFailed;
        }

        var signature: Signature = undefined;
        var recid: c_int = undefined;
        _ = secp256k1lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(self.context, &signature, &recid, &sigstruct);
        signature[64] = @as(u8, @intCast(recid));

        return signature;
    }

    pub fn recoverPubkey(self: Secp256k1, msg: Message, sig: Signature) !PublicKey {
        try checkSignatureRecID(sig);

        var pubkey: PublicKey = undefined;
        if (secp256k1lib.secp256k1_ext_ecdsa_recover(self.context, &pubkey, &sig, &msg) == 0) {
            return error.RecoverFailed;
        }

        return pubkey;
    }

    fn checkSignatureRecID(sig: [65]u8) !void {
        if (sig[64] >= 4) {
            return error.InvalidRecoveryID;
        }
    }
};

test "recover pubkey" {
    var msg: Message = undefined;
    _ = try std.fmt.hexToBytes(&msg, "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008");
    var sig: Signature = undefined;
    _ = try std.fmt.hexToBytes(&sig, "90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301");
    var pubkey1: PublicKey = undefined;
    _ = try std.fmt.hexToBytes(&pubkey1, "04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652");

    var s = try Secp256k1.init();
    const pubkey2 = try s.recoverPubkey(msg, sig);
    try std.testing.expectEqualSlices(u8, &pubkey1, &pubkey2);
}

test "sign and recover" {
    var s = try Secp256k1.init();
    const keypair = try s.generate_keypair();

    var msg: [32]u8 = undefined;
    std.crypto.random.bytes(&msg);

    const sig = try s.sign(msg, keypair.privkey);
    const got_pubkey = try s.recoverPubkey(msg, sig);
    try std.testing.expectEqual(keypair.pubkey, got_pubkey);
}
