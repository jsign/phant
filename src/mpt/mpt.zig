const std = @import("std");
const rlp = @import("zig-rlp");
const types = @import("../types/types.zig");
const crypto = @import("../crypto/crypto.zig");
const hasher = crypto.hasher;
const common = @import("../common/common.zig");
const Allocator = std.mem.Allocator;
const Hash32 = types.Hash32;

pub const empty_mpt_root = common.comptimeHexToBytes("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

const KeyVal = struct {
    nibbles: []const u8,
    value: []const u8,

    pub fn init(allocator: Allocator, key: []const u8, value: []const u8) !KeyVal {
        var nibbles = try allocator.alloc(u8, key.len * 2);
        for (key, 0..) |byte, i| {
            const high = byte >> 4;
            const low = byte & 0x0F;
            nibbles[i * 2] = high;
            nibbles[i * 2 + 1] = low;
        }

        return .{ .nibbles = nibbles, .value = value };
    }
};

fn mptize(allocator: Allocator, list: []const KeyVal) !Hash32 {
    const s = struct {
        fn lessThan(_: void, a: KeyVal, b: KeyVal) bool {
            return std.mem.lessThan(u8, a.nibbles, b.nibbles);
        }
    };
    std.debug.assert(std.sort.isSorted(KeyVal, list, {}, s.lessThan));

    return try getMPTRoot(allocator, list, 0);
}

fn getMPTRoot(allocator: Allocator, list: []const KeyVal, level: usize) !Hash32 {
    // Empty node.
    if (list.len == 0) {
        return empty_mpt_root;
    }

    var out = std.ArrayList(u8).init(allocator);
    defer out.deinit();

    // Leaf node.
    if (list.len == 1) {
        const ln: LeafNode = .{ .extra_nibbles = list[0].nibbles[level..], .value = list[0].value };
        return ln.hash(allocator);
    } else @panic("not implemented");

    return hasher.keccak256(out.items);
}

const LeafNode = struct {
    extra_nibbles: []const u8,
    value: []const u8,

    pub fn hash(self: LeafNode, allocator: Allocator) !Hash32 {
        // Calculate rlp_nibbles which adds the prefix nibble to the key nibbles.
        const required_extra_prefix_nibble = self.extra_nibbles.len % 2 == 0;

        var total_nibbles = self.extra_nibbles.len;
        total_nibbles += if (required_extra_prefix_nibble) 2 else 0;

        var rlp_nibbles = try allocator.alloc(u8, total_nibbles / 2);
        defer allocator.free(rlp_nibbles);
        @memset(rlp_nibbles, 0);

        var curr_byte: usize = undefined;
        var curr_shift: u3 = undefined;
        if (required_extra_prefix_nibble) {
            rlp_nibbles[0] = 0b10 << 4;
            curr_byte = 1;
            curr_shift = 4;
        } else {
            rlp_nibbles[0] = 0b11 << 4;
            curr_byte = 0;
            curr_shift = 0;
        }

        for (self.extra_nibbles) |nibble| {
            rlp_nibbles[curr_byte] |= nibble << curr_shift;
            if (curr_shift == 0)
                curr_byte += 1;
            curr_shift = if (curr_shift == 4) 0 else 4;
        }

        // Calculate the RLP representation of the value.
        const RLPType = struct { prefixed_nibbles: []const u8, value: []const u8 };
        var rlp_repr: RLPType = .{ .prefixed_nibbles = rlp_nibbles, .value = self.value };
        var out = std.ArrayList(u8).init(allocator);
        try rlp.serialize(RLPType, allocator, rlp_repr, &out);

        return hasher.keccak256(out.items);
    }
};

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
    var allocator = arena.allocator();

    const TestCase = struct {
        name: []const u8,
        keyvals: []const KeyVal,
        exp_hash: Hash32,
    };
    const test_cases = [_]TestCase{
        .{
            .name = "empty",
            .keyvals = &[_]KeyVal{},
            .exp_hash = empty_mpt_root,
        },
        .{
            .name = "single",
            .keyvals = &[_]KeyVal{try KeyVal.init(allocator, &[_]u8{ 1, 2, 3, 4 }, "hello")},
            .exp_hash = comptime common.comptimeHexToBytes("6764f7ad0efcbc11b84fe7567773aa4b12bd6b4d35c05bbc3951b58dedb6c8e8"),
        },
    };

    for (test_cases) |tc| {
        const got = try mptize(allocator, tc.keyvals);
        try std.testing.expectEqualSlices(u8, &tc.exp_hash, &got);
    }
}
