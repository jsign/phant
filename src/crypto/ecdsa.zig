const std = @import("std");
const secp256k1 = @import("zig-eth-secp256k1");
const common = @import("../common/common.zig");
pub const Signature = [65]u8;
pub const Message = [32]u8;
pub const PrivateKey = [32]u8;
pub const CompressedPublicKey = [33]u8;
pub const UncompressedPublicKey = [65]u8;

pub const Signer = struct {
    sec: secp256k1.Secp256k1,

    pub fn init() !Signer {
        return Signer{
            .sec = try secp256k1.Secp256k1.init(),
        };
    }

    pub fn erecover(self: Signer, sig: Signature, msg: Message) !UncompressedPublicKey {
        return try self.sec.recoverPubkey(msg, sig);
    }

    pub fn sign(self: Signer, msg: Message, privkey: PrivateKey) !Signature {
        return try self.sec.sign(msg, privkey);
    }
};

// The following test values where generated using geth, as a reference.
const hashed_msg = common.comptimeHexToBytes("0x05e0e0ff09b01e5626daac3165b82afa42be29197b82e8a5a8800740ee7519d2");
const private_key = common.comptimeHexToBytes("0xf457cd3bd0186e342d243ea40ad78fe8e81743f90852e87074e68d8c94c2a42e");
const signature = common.comptimeHexToBytes("0x5a62891eb3e26f3a2344f93a7bad7fe5e670dc45cbdbf0e5bbdba4399238b5e6614caf592f96ee273a2bf018a976e7bf4b63777f9e53ce819d96c5035611400600");
const uncompressed_pubkey = common.comptimeHexToBytes("0x04682bade67348db99074fcaaffef29394192e7e227a2bdb49f930c74358060c6a42df70f7ef8aadd94854abe646e047142fad42811e325afbec4753342d630b1e");
const compressed_pubkey = common.comptimeHexToBytes("0x02682bade67348db99074fcaaffef29394192e7e227a2bdb49f930c74358060c6a");

test "erecover" {
    const signer = try Signer.init();
    const got_pubkey = try signer.erecover(signature, hashed_msg);
    try std.testing.expectEqual(uncompressed_pubkey, got_pubkey);
}
