/// Native precompile implementations for EVM.
/// Only the point evaluation precompile (0x0a, EIP-4844) is implemented here;
/// other precompiles are handled by evmone internally.
const std = @import("std");
const evmc = @cImport({
    @cInclude("evmc/evmc.h");
});
const crypto_kzg = @import("../crypto/kzg.zig");
const types = @import("../types/types.zig");
const Address = types.Address;

const POINT_EVALUATION_ADDRESS: Address = blk: {
    var addr = [_]u8{0} ** 20;
    addr[19] = 0x0a;
    break :blk addr;
};

/// Gas cost for the point evaluation precompile (EIP-4844).
const POINT_EVALUATION_GAS: i64 = 50000;

/// Expected input size: versioned_hash (32) + z (32) + y (32) + commitment (48) + proof (48) = 192
const POINT_EVALUATION_INPUT_SIZE: usize = 192;

/// KZG_VERSIONED_HASH_VERSION_KZG
const VERSIONED_HASH_VERSION: u8 = 0x01;

/// The field modulus for BLS12-381.
const BLS_MODULUS: [32]u8 = .{
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
    0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
};

/// The return data for a successful point evaluation: FIELD_ELEMENTS_PER_BLOB and BLS_MODULUS.
const RETURN_DATA: [64]u8 = blk: {
    var data = [_]u8{0} ** 64;
    // FIELD_ELEMENTS_PER_BLOB = 4096 as big-endian u256
    data[31] = 0x10;
    data[30] = 0x00; // 4096 = 0x1000
    // BLS_MODULUS as big-endian u256
    @memcpy(data[32..64], &BLS_MODULUS);
    break :blk data;
};

var return_data_static: [64]u8 = RETURN_DATA;

/// Check if an address is a precompile that we handle natively.
fn isNativePrecompile(addr: Address, revision: c_uint) bool {
    if (revision >= 12) { // EVMC_CANCUN
        if (std.mem.eql(u8, &addr, &POINT_EVALUATION_ADDRESS)) return true;
    }
    return false;
}

/// Execute a precompile if the address matches. Returns null if not a native precompile.
pub fn execute(addr: Address, input: []const u8, gas_available: i64, revision: c_uint) ?evmc.struct_evmc_result {
    if (!isNativePrecompile(addr, revision)) return null;

    if (std.mem.eql(u8, &addr, &POINT_EVALUATION_ADDRESS)) {
        return pointEvaluation(input, gas_available);
    }

    return null;
}

/// EIP-4844 point evaluation precompile.
/// Input: versioned_hash (32) || z (32) || y (32) || commitment (48) || proof (48)
fn pointEvaluation(input: []const u8, gas_available: i64) evmc.struct_evmc_result {
    // Check gas
    if (gas_available < POINT_EVALUATION_GAS) {
        return failResult(evmc.EVMC_OUT_OF_GAS);
    }
    if (input.len != POINT_EVALUATION_INPUT_SIZE) {
        return failResult(evmc.EVMC_PRECOMPILE_FAILURE);
    }

    const versioned_hash = input[0..32];
    const z = input[32..64];
    const y = input[64..96];
    const commitment = input[96..144];
    const proof = input[144..192];

    // Verify versioned hash matches commitment
    if (versioned_hash[0] != VERSIONED_HASH_VERSION) {
        return failResult(evmc.EVMC_PRECOMPILE_FAILURE);
    }

    // Compute kzg_to_versioned_hash(commitment) and compare
    var commitment_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(commitment, &commitment_hash, .{});
    commitment_hash[0] = VERSIONED_HASH_VERSION;

    if (!std.mem.eql(u8, versioned_hash, &commitment_hash)) {
        return failResult(evmc.EVMC_PRECOMPILE_FAILURE);
    }

    // Verify KZG proof using c-kzg
    const c_commitment: *const crypto_kzg.KZGCommitment = @ptrCast(commitment.ptr);
    const c_proof: *const crypto_kzg.KZGProof = @ptrCast(proof.ptr);

    // Load trusted setup (lazily initialized)
    const setup = getTrustedSetup() orelse return failResult(evmc.EVMC_PRECOMPILE_FAILURE);

    const ok = setup.verifyProof(c_commitment, z[0..32], y[0..32], c_proof) catch {
        return failResult(evmc.EVMC_PRECOMPILE_FAILURE);
    };

    if (!ok) {
        return failResult(evmc.EVMC_PRECOMPILE_FAILURE);
    }

    // Return FIELD_ELEMENTS_PER_BLOB and BLS_MODULUS
    return .{
        .status_code = evmc.EVMC_SUCCESS,
        .gas_left = gas_available - POINT_EVALUATION_GAS,
        .gas_refund = 0,
        .output_data = &return_data_static,
        .output_size = 64,
        .release = null,
        .create_address = std.mem.zeroes(evmc.struct_evmc_address),
        .padding = [_]u8{0} ** 4,
    };
}

fn failResult(status: c_uint) evmc.struct_evmc_result {
    return .{
        .status_code = status,
        .gas_left = 0,
        .gas_refund = 0,
        .output_data = null,
        .output_size = 0,
        .release = null,
        .create_address = std.mem.zeroes(evmc.struct_evmc_address),
        .padding = [_]u8{0} ** 4,
    };
}

/// Lazily initialized trusted setup singleton.
var trusted_setup: ?crypto_kzg.TrustedSetup = null;
var setup_initialized: bool = false;

fn getTrustedSetup() ?*const crypto_kzg.TrustedSetup {
    if (setup_initialized) {
        if (trusted_setup) |*ts| return ts;
        return null;
    }
    setup_initialized = true;
    trusted_setup = crypto_kzg.TrustedSetup.initFromFile("c-kzg-4844/src/setup/trusted_setup.txt") catch {
        std.log.err("Failed to load KZG trusted setup", .{});
        return null;
    };
    if (trusted_setup) |*ts| return ts;
    return null;
}
