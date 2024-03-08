const std = @import("std");
const rlp = @import("zig-rlp");
const types = @import("../types/types.zig");
const common = @import("../common/common.zig");
const Allocator = std.mem.Allocator;
const Hash32 = types.Hash32;

pub const empty_mpt_root = common.comptimeHexToBytes("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

const KeyVal = struct {
    key: []const u8,
    value: []const u8,
};

fn mptize(list: []KeyVal) Hash32 {
    const s = struct {
        fn lessThan(_: void, a: KeyVal, b: KeyVal) bool {
            return std.mem.lessThan(u8, a.key, b.key);
        }
    };
    std.sort.pdq(KeyVal, list, {}, s.lessThan);

    return getMPTRoot(list, 0);
}

fn getMPTRoot(list: []KeyVal, level: usize) Hash32 {
    _ = level;
    if (list.len == 0) {
        return empty_mpt_root;
    }
    return [_]u8{0} ** 32;
}

// indexToRLP returns the RLP representation of the index.
// The caller is responsible for freeing the returned slice.
fn indexToRLP(allocator: Allocator, index: u16) ![]const u8 {
    if (index == 0) {
        return &[_]u8{0x80};
    }
    if (index <= 127) { // Small values RLP optimized.
        var out = try allocator.alloc(u8, 1);
        out[0] = @intCast(index);
        return out;
    }
    if (index < 1 << 8) { // 1 byte.
        var out = try allocator.alloc(u8, 1 + 1);
        out[0] = 0x81;
        out[1] = @intCast(index);
        return out;
    }
    // 2 bytes.
    var out = try allocator.alloc(u8, 1 + 2);
    out[0] = 0x82;
    std.mem.writeInt(u16, out[1..3], index, std.builtin.Endian.Big);
    return out;
}

test "basic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    _ = allocator;

    const TestCase = struct {
        name: []const u8,
        keyvals: []KeyVal,
        exp_hash: Hash32,
    };
    const test_cases = [_]TestCase{
        .{ .name = "empty", .keyvals = &[_]KeyVal{}, .exp_hash = empty_mpt_root },
    };

    inline for (test_cases) |tc| {
        const got = mptize(tc.keyvals);
        try std.testing.expectEqualSlices(u8, &tc.exp_hash, &got);
    }
}
