const Keccak = @import("std").crypto.hash.sha3.Keccak256;
const Hash32 = @import("../types/types.zig").Hash32;

pub fn keccak256(data: []const u8) Hash32 {
    var ret: Hash32 = undefined;
    Keccak.hash(data, &ret, .{});
    return ret;
}

pub fn keccak256WithPrefix(prefix: []const u8, data: []const u8) !Hash32 {
    var h = Keccak.init(.{});
    _ = try h.writer().write(prefix);
    _ = try h.writer().write(data);
    var ret: Hash32 = undefined;
    h.final(&ret);
    return ret;
}
