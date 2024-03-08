const std = @import("std");
const rlp = @import("zig-rlp");
const types = @import("../types/types.zig");
const crypto = @import("../crypto/crypto.zig");
const hasher = crypto.hasher;
const common = @import("../common/common.zig");
const Allocator = std.mem.Allocator;
const Hash32 = types.Hash32;

const empty_mpt_root = common.comptimeHexToBytes("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");

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

fn mptize(arena: Allocator, list: []const KeyVal) !Hash32 {
    const s = struct {
        fn lessThan(_: void, a: KeyVal, b: KeyVal) bool {
            return std.mem.lessThan(u8, a.nibbles, b.nibbles);
        }
    };
    std.debug.assert(std.sort.isSorted(KeyVal, list, {}, s.lessThan));

    const root = try insertNode(arena, list, 0);
    const root_hash = try root.hash(arena);

    return root_hash.*;
}

fn insertNode(allocator: Allocator, list: []const KeyVal, level: usize) !Node {
    // Empty node.
    if (list.len == 0) {
        return .{ .empty_node = .{} };
    }

    // Leaf node.
    if (list.len == 1) {
        return .{ .leaf_node = .{ .extra_nibbles = list[0].nibbles[level..], .value = list[0].value } };
    }

    var bn = BranchNode.init();
    var start = level;
    while (start < list.len) {
        var end = start;
        for (start..list.len) |i| {
            if (list[start].nibbles[level] != list[i].nibbles[level]) {
                end = i;
                break;
            }
            end += 1;
        }

        // Extension node.
        if (start == 0 and end == list.len) {
            @panic("TODO");
        }

        const nibble_group = list[start..end];
        const node = try insertNode(allocator, nibble_group, level + 1);
        const node_rlp = try node.encodeRLP(allocator);
        bn.slot[list[start].nibbles[level]] = if (node_rlp.len < 32) try node.getBranchValue(allocator) else .{ .value = try node.hash(allocator) };

        start = end;
    }

    return .{ .branch_node = bn };
}

const Node = union(enum) {
    empty_node: EmptyNode,
    branch_node: BranchNode,
    leaf_node: LeafNode,

    pub fn getBranchValue(self: Node, allocator: Allocator) !GenericRLPValue {
        return switch (self) {
            inline else => |n| n.getBranchValue(allocator),
        };
    }

    pub fn encodeRLP(self: Node, allocator: Allocator) ![]const u8 {
        return switch (self) {
            inline else => |n| n.encodeRLP(allocator),
        };
    }

    // hash returns a heap-allocated Hash32.
    pub fn hash(self: Node, allocator: Allocator) !*const Hash32 {
        return switch (self) {
            inline else => |n| n.hash(allocator),
        };
    }
};

const EmptyNode = struct {
    pub fn getBranchValue(self: EmptyNode, allocator: Allocator) GenericRLPValue {
        _ = allocator;
        _ = self;
        return .{ .value = &[_]u8{} };
    }

    pub fn encodeRLP(self: EmptyNode, allocator: Allocator) ![]const u8 {
        _ = allocator;
        _ = self;
        return &[_]u8{};
    }
    pub fn hash(self: EmptyNode, allocator: Allocator) !*const Hash32 {
        _ = allocator;
        _ = self;
        return &empty_mpt_root;
    }
};

const GenericRLPValue = union(enum) {
    value: []const u8,
    list: []const GenericRLPValue,

    pub fn encodeToRLP(self: GenericRLPValue, allocator: Allocator, list: *std.ArrayList(u8)) !void {
        switch (self) {
            inline else => |v| try rlp.serialize(@TypeOf(v), allocator, v, list),
        }
    }
};

const BranchNode = struct {
    slot: [16]GenericRLPValue,
    value: []const u8,

    pub fn init() BranchNode {
        return .{
            .slot = [_]GenericRLPValue{.{ .value = &[_]u8{} }} ** 16,
            .value = &[_]u8{},
        };
    }

    pub fn getBranchValue(self: BranchNode, allocator: Allocator) !GenericRLPValue {
        var rlp_value = try allocator.alloc(GenericRLPValue, 17);
        for (self.slot, 0..) |slot, i| {
            rlp_value[i] = slot;
        }
        rlp_value[16] = .{ .value = self.value };

        return .{ .list = rlp_value };
    }

    pub fn encodeRLP(self: BranchNode, allocator: Allocator) ![]const u8 {
        const rlp_value = try self.getBranchValue(allocator);
        var out = std.ArrayList(u8).init(allocator);
        try rlp.serialize(@TypeOf(rlp_value), allocator, rlp_value, &out);

        return out.toOwnedSlice();
    }

    pub fn hash(self: BranchNode, allocator: Allocator) !*Hash32 {
        var rlp_encoded = try self.encodeRLP(allocator);

        var hsh = try allocator.create(Hash32);
        @memcpy(hsh, &hasher.keccak256(rlp_encoded));
        return hsh;
    }
};

const LeafNode = struct {
    extra_nibbles: []const u8,
    value: []const u8,

    pub fn getBranchValue(self: LeafNode, allocator: Allocator) !GenericRLPValue {
        // Calculate rlp_nibbles which adds the prefix nibble to the key nibbles.
        const required_extra_prefix_nibble = self.extra_nibbles.len % 2 == 0;

        var total_nibbles = self.extra_nibbles.len;
        total_nibbles += if (required_extra_prefix_nibble) 2 else 1;

        var rlp_nibbles = try allocator.alloc(u8, total_nibbles / 2);
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
        var out = try allocator.alloc(GenericRLPValue, 2);
        out[0] = .{ .value = rlp_nibbles };
        out[1] = .{ .value = self.value };

        return .{ .list = out };
    }

    pub fn encodeRLP(self: LeafNode, allocator: Allocator) ![]const u8 {
        const bv = try self.getBranchValue(allocator);
        var out = std.ArrayList(u8).init(allocator);
        defer out.deinit();

        try rlp.serialize(GenericRLPValue, allocator, bv, &out);

        return out.toOwnedSlice();
    }

    pub fn hash(self: LeafNode, allocator: Allocator) !*Hash32 {
        var rlp_value = try self.encodeRLP(allocator);

        var hsh = try allocator.create(Hash32);
        @memcpy(hsh, &hasher.keccak256(rlp_value));

        return hsh;
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
            .name = "single key - root is a leaf node",
            .keyvals = &[_]KeyVal{try KeyVal.init(allocator, &[_]u8{ 1, 2, 3, 4 }, "hello")},
            .exp_hash = comptime common.comptimeHexToBytes("6764f7ad0efcbc11b84fe7567773aa4b12bd6b4d35c05bbc3951b58dedb6c8e8"),
        },
        .{
            .name = "two keys - root is a branch node with two leaf nodes",
            .keyvals = &[_]KeyVal{
                try KeyVal.init(allocator, &[_]u8{ 1, 2, 3, 4 }, "hello1"),
                try KeyVal.init(allocator, &[_]u8{ 255, 2, 3, 4 }, "hello2"),
            },
            .exp_hash = comptime common.comptimeHexToBytes("5c474c00e417f587322ae674c948f04e2c217f95bd1dac806af14fa46f8fa403"),
        },
    };

    for (test_cases) |tc| {
        const got = try mptize(allocator, tc.keyvals);
        try std.testing.expectEqualSlices(u8, &tc.exp_hash, &got);
    }
}
