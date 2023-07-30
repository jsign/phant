const Bytes31 = @import("base.zig").Bytes31;

// Verkle Tree types.
pub const Stem = [31]u8;
pub const TreeKey = [32]u8;
pub const TreeValue = ?[32]u8;

// Verkle Proof types.
pub const VERKLE_WIDTH: usize = 256;
pub const IPA_PROOF_DEPTH = 8;
pub const BanderwagonFieldElement = [32]u8;
pub const BanderwagonGroupElement = [32]u8;

pub const IpaProof = struct {
    cl: [IPA_PROOF_DEPTH]BanderwagonGroupElement,
    cr: [IPA_PROOF_DEPTH]BanderwagonGroupElement,
    final_evaluation: BanderwagonFieldElement,
};

pub const VerkleProof = struct {
    other_stems: []Bytes31,
    depth_extension_present: []const u8,
    commitments_by_path: []BanderwagonGroupElement,
    d: BanderwagonGroupElement,
    ipa_proof: IpaProof,
};

pub const SuffixStateDiff = struct {
    suffix: u8,
    current_value: ?[32]u8,
};

pub const StemStateDiff = struct {
    stem: Stem,
    suffix_diffs: []const SuffixStateDiff,
};

pub const StateDiff = []const StemStateDiff;
