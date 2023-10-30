const std = @import("std");
const fmt = std.fmt;
const Allocator = std.mem.Allocator;

// This function turns an optionally '0x'-prefixed hex string
// to a types.Hash32
pub fn prefixedhex2hash(dst: []u8, src: []const u8) !void {
    if (src.len < 2 or src.len % 2 != 0) {
        return error.InvalidInput;
    }
    var skip0x: usize = if (src[1] == 'X' or src[1] == 'x') 2 else 0;
    if (src[skip0x..].len != 2 * dst.len) {
        return error.InvalidOutputLength;
    }
    _ = try fmt.hexToBytes(dst, src[skip0x..]);
}

// This function turns an optionally '0x'-prefixed hex string
// to a byte slice
pub fn prefixedhex2byteslice(allocator: Allocator, src: []const u8) ![]u8 {
    // TODO catch the 0x0 corner case
    if (src.len < 2 or src.len % 2 != 0) {
        return error.InvalidInput;
    }
    var skip0x: usize = if (src[1] == 'X' or src[1] == 'x') 2 else 0;
    // TODO when refactoring, ensure the alloc is also made in the equivalent for prefixedhex2hash
    var dst: []u8 = try allocator.alloc(u8, src[skip0x..].len / 2);

    _ = try fmt.hexToBytes(dst[0..], src[skip0x..]);

    return dst;
}

// This function turns an optionally '0x'-prefixed hex string
// to a u64
pub fn prefixedhex2u64(src: []const u8) !u64 {
    // execution engine integers can be odd-length :facepalm:
    if (src.len < 3) {
        return error.InvalidInput;
    }

    var skip0x: usize = if (src[1] == 'X' or src[1] == 'x') 2 else 0;

    return std.fmt.parseInt(u64, src[skip0x..], 16);
}
