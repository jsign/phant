const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // libsecp256k1 static C library.
    const libsecp256k1 = b.addStaticLibrary(.{
        .name = "secp256k1",
        .target = target,
        .optimize = optimize,
    });
    libsecp256k1.addIncludePath(b.path("libsecp256k1"));
    libsecp256k1.addIncludePath(b.path("libsecp256k1/src"));
    libsecp256k1.defineCMacro("USE_FIELD_10X26", "1");
    libsecp256k1.defineCMacro("USE_SCALAR_8X32", "1");
    libsecp256k1.defineCMacro("USE_ENDOMORPHISM", "1");
    libsecp256k1.defineCMacro("USE_NUM_NONE", "1");
    libsecp256k1.defineCMacro("USE_FIELD_INV_BUILTIN", "1");
    libsecp256k1.defineCMacro("USE_SCALAR_INV_BUILTIN", "1");
    libsecp256k1.addCSourceFile(.{ .file = b.path("ext.c"), .flags = &[0][]const u8{} });
    libsecp256k1.linkLibC();
    b.installArtifact(libsecp256k1);

    // Run command.
    const exe = b.addExecutable(.{
        .name = "zig-eth-secp256k1",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.addIncludePath(b.path("."));
    exe.addIncludePath(b.path("libsecp256k1"));
    exe.linkLibrary(libsecp256k1);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    b.installArtifact(exe);

    // Tests.
    const main_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    main_tests.addIncludePath(b.path("."));
    main_tests.addIncludePath(b.path("libsecp256k1"));
    main_tests.linkLibrary(libsecp256k1);

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    // Exported modules.
    _ = b.addModule("zig-eth-secp256k1", .{ .root_source_file = b.path("src/secp256k1.zig") });
}
