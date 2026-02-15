const Build = @import("std").Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("zig-rlp", Build.Module.CreateOptions{
        .root_source_file = b.path("src/rlp.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addStaticLibrary(.{
        .name = "zig-rlp",
        .root_source_file = .{ .cwd_relative = "src/serialize.zig" },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    var main_tests = b.addRunArtifact(b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/serialize.zig" },
        .target = target,
        .optimize = optimize,
    }));
    var deser_tests = b.addRunArtifact(b.addTest(.{
        .root_source_file = .{ .cwd_relative = "src/deserialize.zig" },
        .target = target,
        .optimize = optimize,
    }));

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
    test_step.dependOn(&deser_tests.step);
}
