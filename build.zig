const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dep_rlp = b.dependency("rlp", .{ .target = target, .optimize = optimize });
    const depSecp256k1 = b.dependency("zig_eth_secp256k1", .{ .target = target, .optimize = optimize });
    const mod_secp256k1 = depSecp256k1.module("zig-eth-secp256k1");

    // Build evmone as a native static library (no cmake needed)
    const evmone_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });

    // evmone C++ source files
    evmone_mod.addCSourceFiles(.{
        .root = b.path("evmone/lib/evmone"),
        .files = &.{
            "advanced_analysis.cpp",
            "advanced_execution.cpp",
            "advanced_instructions.cpp",
            "baseline_analysis.cpp",
            "baseline_execution.cpp",
            "baseline_instruction_table.cpp",
            "eof.cpp",
            "instructions_calls.cpp",
            "instructions_storage.cpp",
            "tracing.cpp",
            "vm.cpp",
        },
        .flags = &.{ "-std=c++20", "-fno-exceptions", "-fno-rtti", "-DPROJECT_VERSION=\"0.12.0\"" },
    });

    // keccak C source from ethash
    evmone_mod.addCSourceFiles(.{
        .root = b.path("evmone/ethash/lib/keccak"),
        .files = &.{"keccak.c"},
        .flags = &.{"-std=c11"},
    });

    // Shim for __cpu_model/__cpu_indicator_init (GCC runtime symbols used by keccak BMI dispatch)
    evmone_mod.addCSourceFiles(.{
        .root = b.path("."),
        .files = &.{"cpu_compat.c"},
        .flags = &.{"-std=c11"},
    });

    // Include paths for evmone and its dependencies
    evmone_mod.addIncludePath(b.path("evmone/include"));
    evmone_mod.addIncludePath(b.path("evmone/lib/evmone"));
    evmone_mod.addIncludePath(b.path("evmone/evmc/include"));
    evmone_mod.addIncludePath(b.path("evmone/intx/include"));
    evmone_mod.addIncludePath(b.path("evmone/ethash/include"));

    const evmone_lib = b.addLibrary(.{
        .name = "evmone",
        .linkage = .static,
        .root_module = evmone_mod,
    });

    // Create the phant library module (exported for downstream consumers)
    const phant_mod = b.addModule("phant", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "zig-rlp", .module = dep_rlp.module("zig-rlp") },
            .{ .name = "zig-eth-secp256k1", .module = mod_secp256k1 },
        },
    });
    phant_mod.addIncludePath(b.path("evmone/include/evmone"));
    phant_mod.addIncludePath(b.path("evmone/evmc/include"));
    phant_mod.linkLibrary(evmone_lib);
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
        },
    });
    test_mod.addIncludePath(b.path("evmone/include/evmone"));
    test_mod.addIncludePath(b.path("evmone/evmc/include"));
    test_mod.linkLibrary(evmone_lib);
    test_mod.linkLibrary(depSecp256k1.artifact("secp256k1"));

    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });

    const run_unit_tests = b.addRunArtifact(unit_tests);
    run_unit_tests.has_side_effects = true;

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
