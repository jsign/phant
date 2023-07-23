pub const VERKLE_WIDTH: usize = 256;
pub const Stem = [31]u8;

pub const SuffixStateDiff = struct {
    suffix: u8,
    current_value: ?[32]u8,
    // new_value : ?[32]u8, // Currently, this is disabled.
};

pub const StemStateDiff = struct {
    stem: Stem,
    suffix_diffs: []const SuffixStateDiff,
};

pub const StateDiff = []const StemStateDiff;

pub const TreeKey = [32]u8;
pub const TreeValue = ?[32]u8;
