const std = @import("std");

pub const state = @import("state/state.zig");
pub const types = @import("types/types.zig");
pub const blockchain = @import("blockchain/blockchain.zig");
pub const crypto = @import("crypto/crypto.zig");
pub const signer = @import("signer/signer.zig");
pub const engine_api = @import("engine_api/engine_api.zig");
pub const mpt = @import("mpt/mpt.zig");
pub const config = @import("config/config.zig");

test "tests" {
    std.testing.log_level = .debug;

    std.testing.refAllDeclsRecursive(@import("blockchain/blockchain.zig"));
    std.testing.refAllDeclsRecursive(@import("config/config.zig"));
    std.testing.refAllDeclsRecursive(@import("crypto/crypto.zig"));
    std.testing.refAllDeclsRecursive(@import("engine_api/engine_api.zig"));
    std.testing.refAllDeclsRecursive(@import("tests/spec_tests.zig"));
    std.testing.refAllDeclsRecursive(@import("tests/custom_tests.zig"));
    std.testing.refAllDeclsRecursive(@import("state/state.zig"));
    std.testing.refAllDeclsRecursive(@import("types/types.zig"));
    std.testing.refAllDeclsRecursive(@import("mpt/mpt.zig"));
}
