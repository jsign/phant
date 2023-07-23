// Block types.
// NOTE: these structures have an old format since we're using block2.rlp.
//       at some point we'll update it.
pub const VerkleBlock = struct {
    header: VerkleHeader,
};

pub const VerkleHeader = struct {
    parent_hash: Hash32,
    uncle_hash: Hash32,
    fee_recipient: ExecutionAddress,
    state_root: Bytes32,
    transactions_root: Bytes32,
    receipts_root: Bytes32,
    logs_bloom: [BYTES_PER_LOGS_BLOOM]u8,
    prev_randao: Bytes32,
    block_number: u64,
    gas_limit: u64,
    gas_used: u64,
    timestamp: u64,
    extra_data: []const u8,
    mix_hash: u256,
    nonce: [8]u8,
    base_fee_per_gas: [4]u8,

    // Verkle.
    // verkle_proof: VerkleProof,
};
const BYTES_PER_LOGS_BLOOM = 256;
const Hash32 = [32]u8;
const ExecutionAddress = [20]u8;
const Bytes32 = [32]u8;
const Bytes31 = [31]u8;

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
