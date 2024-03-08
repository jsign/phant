const std = @import("std");

test "tests" {
    std.testing.log_level = .debug;

    // std.testing.refAllDeclsRecursive(@import("blockchain/blockchain.zig"));
    // std.testing.refAllDeclsRecursive(@import("config/config.zig"));
    // std.testing.refAllDeclsRecursive(@import("crypto/crypto.zig"));
    // std.testing.refAllDeclsRecursive(@import("engine_api/engine_api.zig"));
    // std.testing.refAllDeclsRecursive(@import("tests/spec_tests.zig"));
    // std.testing.refAllDeclsRecursive(@import("state/state.zig"));
    // std.testing.refAllDeclsRecursive(@import("types/types.zig"));
    std.testing.refAllDeclsRecursive(@import("mpt/mpt.zig"));
}
