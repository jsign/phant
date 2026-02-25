/// KZG bindings for c-kzg-4844.
/// Provides blob commitment/proof verification for EIP-4844.
const std = @import("std");

const c = @cImport({
    @cInclude("ckzg.h");
});

pub const BYTES_PER_BLOB = c.BYTES_PER_BLOB;
pub const BYTES_PER_COMMITMENT = c.BYTES_PER_COMMITMENT;
pub const BYTES_PER_PROOF = c.BYTES_PER_PROOF;
pub const BYTES_PER_FIELD_ELEMENT = c.BYTES_PER_FIELD_ELEMENT;
pub const FIELD_ELEMENTS_PER_BLOB = c.FIELD_ELEMENTS_PER_BLOB;

pub const Blob = [BYTES_PER_BLOB]u8;
pub const KZGCommitment = [BYTES_PER_COMMITMENT]u8;
pub const KZGProof = [BYTES_PER_PROOF]u8;

pub const KZGError = error{
    BadArgs,
    InternalError,
    MallocError,
};

const KZGSettings = c.KZGSettings;

/// Wrapper around c-kzg KZGSettings with deferred cleanup.
pub const TrustedSetup = struct {
    settings: KZGSettings,

    /// Load trusted setup from the embedded file.
    pub fn init() !TrustedSetup {
        var self: TrustedSetup = undefined;
        // Load the default trusted setup bundled with c-kzg
        const setup_path = "c-kzg-4844/src/setup/trusted_setup.txt";
        const file = c.fopen(setup_path, "r") orelse return KZGError.BadArgs;
        defer _ = c.fclose(file);
        const ret = c.load_trusted_setup_file(&self.settings, file, 0);
        if (ret != c.C_KZG_OK) return mapError(ret);
        return self;
    }

    /// Load trusted setup from a file path.
    pub fn initFromFile(path: [*:0]const u8) !TrustedSetup {
        var self: TrustedSetup = undefined;
        const file = c.fopen(path, "r") orelse return KZGError.BadArgs;
        defer _ = c.fclose(file);
        const ret = c.load_trusted_setup_file(&self.settings, file, 0);
        if (ret != c.C_KZG_OK) return mapError(ret);
        return self;
    }

    pub fn deinit(self: *TrustedSetup) void {
        c.free_trusted_setup(&self.settings);
    }

    /// Compute the KZG commitment for a blob.
    pub fn blobToCommitment(self: *const TrustedSetup, blob: *const Blob) !KZGCommitment {
        var commitment: c.KZGCommitment = undefined;
        const ret = c.blob_to_kzg_commitment(
            &commitment,
            @ptrCast(blob),
            &self.settings,
        );
        if (ret != c.C_KZG_OK) return mapError(ret);
        return commitment.bytes;
    }

    /// Compute a KZG proof for a blob at a given point.
    pub fn computeBlobProof(self: *const TrustedSetup, blob: *const Blob, commitment: *const KZGCommitment) !KZGProof {
        var proof: c.KZGProof = undefined;
        const ret = c.compute_blob_kzg_proof(
            &proof,
            @ptrCast(blob),
            @ptrCast(commitment),
            &self.settings,
        );
        if (ret != c.C_KZG_OK) return mapError(ret);
        return proof.bytes;
    }

    /// Verify a blob KZG proof.
    pub fn verifyBlobProof(self: *const TrustedSetup, blob: *const Blob, commitment: *const KZGCommitment, proof: *const KZGProof) !bool {
        var ok: bool = false;
        const ret = c.verify_blob_kzg_proof(
            &ok,
            @ptrCast(blob),
            @ptrCast(commitment),
            @ptrCast(proof),
            &self.settings,
        );
        if (ret != c.C_KZG_OK) return mapError(ret);
        return ok;
    }

    /// Verify a KZG proof for a single point.
    pub fn verifyProof(self: *const TrustedSetup, commitment: *const KZGCommitment, z: *const [BYTES_PER_FIELD_ELEMENT]u8, y: *const [BYTES_PER_FIELD_ELEMENT]u8, proof: *const KZGProof) !bool {
        var ok: bool = false;
        const ret = c.verify_kzg_proof(
            &ok,
            @ptrCast(commitment),
            @ptrCast(z),
            @ptrCast(y),
            @ptrCast(proof),
            &self.settings,
        );
        if (ret != c.C_KZG_OK) return mapError(ret);
        return ok;
    }
};

fn mapError(ret: c.C_KZG_RET) KZGError {
    return switch (ret) {
        c.C_KZG_BADARGS => KZGError.BadArgs,
        c.C_KZG_MALLOC => KZGError.MallocError,
        else => KZGError.InternalError,
    };
}

test "kzg constants" {
    try std.testing.expectEqual(@as(usize, 131072), BYTES_PER_BLOB);
    try std.testing.expectEqual(@as(usize, 48), BYTES_PER_COMMITMENT);
    try std.testing.expectEqual(@as(usize, 48), BYTES_PER_PROOF);
    try std.testing.expectEqual(@as(usize, 4096), FIELD_ELEMENTS_PER_BLOB);
}
