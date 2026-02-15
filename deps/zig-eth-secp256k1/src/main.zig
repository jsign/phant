const std = @import("std");
const ethsecp = @import("secp256k1.zig");

pub fn main() !void {
    _ = try ethsecp.Secp256k1.init();
}

test "secp" {
    _ = @import("secp256k1.zig");
}
