const Keccak = @import("std").crypto.hash.sha3.Keccak256;

pub fn keccak256(data: []const u8) [32]u8 {
    var ret: [32]u8 = undefined;
    Keccak.hash(data, &ret, .{});
    return ret;
}
