const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dep_rlp = b.dependency("rlp", .{ .target = target, .optimize = optimize });
    const depSecp256k1 = b.dependency("zig_eth_secp256k1", .{ .target = target, .optimize = optimize });
    const mod_secp256k1 = depSecp256k1.module("zig-eth-secp256k1");
    const zigcli = b.dependency("zigcli", .{});

    const evmone_cmake_config_step = b.addSystemCommand(&.{ "cmake", "-S", "evmone", "-B", "zig-out/evmone_build" });
    const evmone_cmake_build_step = b.addSystemCommand(&.{ "cmake", "--build", "zig-out/evmone_build" });
    evmone_cmake_build_step.step.dependOn(&evmone_cmake_config_step.step);

    // Create the phant library module (exported for downstream consumers)
    const phant_mod = b.addModule("phant", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "zig-rlp", .module = dep_rlp.module("zig-rlp") },
            .{ .name = "zig-eth-secp256k1", .module = mod_secp256k1 },
            .{ .name = "pretty-table", .module = zigcli.module("pretty-table") },
        },
    });
    phant_mod.addIncludePath(b.path("evmone/include/evmone"));
    phant_mod.addIncludePath(b.path("evmone/evmc/include"));
    phant_mod.addLibraryPath(b.path("zig-out/evmone_build/lib"));
    phant_mod.linkSystemLibrary("evmone", .{});
    phant_mod.linkLibrary(depSecp256k1.artifact("secp256k1"));

    // Unit tests
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "zig-rlp", .module = dep_rlp.module("zig-rlp") },
            .{ .name = "zig-eth-secp256k1", .module = mod_secp256k1 },
            .{ .name = "pretty-table", .module = zigcli.module("pretty-table") },
        },
    });
    test_mod.addLibraryPath(b.path("zig-out/evmone_build/lib"));
    test_mod.linkSystemLibrary("evmone", .{});
    test_mod.addIncludePath(b.path("evmone/include/evmone"));
    test_mod.addIncludePath(b.path("evmone/evmc/include"));
    test_mod.linkLibrary(depSecp256k1.artifact("secp256k1"));

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    run_unit_tests.has_side_effects = true;

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
