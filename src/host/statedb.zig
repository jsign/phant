const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types.zig");

pub const StateDb = @This();

db: std.AutoHashMap(types.TreeKey, types.TreeValue),

pub fn newStateDb(allocator: Allocator, state_diff: types.StateDiff) !StateDb {
    var db = std.AutoHashMap(types.TreeKey, types.TreeValue).init(allocator);
    try db.ensureTotalCapacity(@intCast(state_diff.len * types.VERKLE_WIDTH));
    for (state_diff) |stem_values| {
        var treeKey: types.TreeKey = undefined;
        @memcpy(treeKey[0..31], &stem_values.stem);
        for (stem_values.suffix_diffs) |suffix_value| {
            treeKey[31] = suffix_value.suffix;
            db.putAssumeCapacity(treeKey, suffix_value.current_value);
        }
    }
    return StateDb{
        .db = db,
    };
}

pub fn get(self: *const StateDb, tree_key: types.TreeKey) ?types.TreeValue {
    return self.db.get(tree_key);
}

pub fn deinit(self: *StateDb) void {
    self.db.deinit();
}

var test_allocator = std.testing.allocator;

test "new" {
    const stemStateDiff1 = types.StemStateDiff{
        .stem = hexToStem("000001"),
        .suffix_diffs = &indexValues(.{ ._3 = [_]u8{10} }),
    };
    const block_state_diff: types.StateDiff = &[_]types.StemStateDiff{stemStateDiff1};
    var statedb = try newStateDb(test_allocator, block_state_diff);
    defer statedb.deinit();
}

// TODO: get tests.

fn hexToStem(comptime hex: []const u8) types.Stem {
    if (hex.len > 31) {
        @compileError("hexToStem: hex too long");
    }
    var stem: types.Stem = undefined;
    _ = std.fmt.hexToBytes(stem[stem.len - hex.len / 2 ..], hex) catch unreachable;

    return stem;
}

fn indexValues(comptime values: anytype) [@typeInfo(@TypeOf(values)).Struct.fields.len]types.SuffixStateDiff {
    const ti = @typeInfo(@TypeOf(values));
    if (ti != .Struct) {
        @compileError(@typeName(@TypeOf(values)));
    }

    var suffix_diffs: [ti.Struct.fields.len]types.SuffixStateDiff = undefined;
    inline for (ti.Struct.fields, 0..) |f, i| {
        if (f.name[0] != '_') {
            @compileError("indexValues: not a valid suffix");
        }
        const index = std.fmt.parseInt(u8, f.name[1..], 10) catch unreachable;

        suffix_diffs[i].suffix = index;
        suffix_diffs[i].current_value = [_]u8{0} ** 32;
        const val = @field(values, f.name);
        @memcpy(suffix_diffs[i].current_value.?[32 - val.len ..], &val);
    }

    return suffix_diffs;
}
