const std = @import("std");
const LazyPath = std.Build.LazyPath;

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    const mod_rlp = b.dependency("zig-rlp", .{}).module("zig-rlp");

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const ethash = b.addStaticLibrary(.{
        .name = "ethash",
        .optimize = optimize,
        .target = target,
    });
    const cflags = [_][]const u8{
        "-Wall",                       "-O3",                    "-fvisibility=hidden",
        "-fvisibility-inlines-hidden", "-Wpedantic",             "-Werror",
        "-Wextra",                     "-Wshadow",               "-Wconversion",
        "-Wsign-conversion",           "-Wno-unknown-pragmas",   "-fno-stack-protector",
        "-Wimplicit-fallthrough",      "-Wmissing-declarations", "-Wno-attributes",
        "-Wextra-semi",                "-fno-exceptions",        "-fno-rtti",
        "-Wno-strict-prototypes", // this one is used by glue.c to avoid a warning that does not disappear when the prototype is added.
    };
    ethash.addCSourceFiles(&[_][]const u8{"ethash/lib/keccak/keccak.c"}, &cflags);
    ethash.addIncludePath(LazyPath{ .path = "ethash/include" });
    ethash.linkLibC();
    ethash.linkLibCpp();
    b.installArtifact(ethash);

    const evmone = b.addStaticLibrary(.{
        .name = "evmone",
        .optimize = optimize,
        .target = target,
    });
    const cppflags = [_][]const u8{
        "-Wall",                "-std=c++20",                  "-O3",
        "-fvisibility=hidden",  "-fvisibility-inlines-hidden", "-Wpedantic",
        "-Werror",              "-Wextra",                     "-Wshadow",
        "-Wconversion",         "-Wsign-conversion",           "-Wno-unknown-pragmas",
        "-fno-stack-protector", "-Wimplicit-fallthrough",      "-Wmissing-declarations",
        "-Wno-attributes",      "-Wextra-semi",                "-fno-exceptions",
        "-fno-rtti",
    };
    evmone.addCSourceFiles(&[_][]const u8{
        "evmone/lib/evmone/advanced_analysis.cpp",
        "evmone/lib/evmone/eof.cpp",
        "evmone/lib/evmone/advanced_execution.cpp",
        "evmone/lib/evmone/instructions_calls.cpp",
        "evmone/lib/evmone/advanced_instructions.cpp",
        "evmone/lib/evmone/instructions_storage.cpp",
        "evmone/lib/evmone/baseline.cpp",
        "evmone/lib/evmone/tracing.cpp",
        "evmone/lib/evmone/baseline_instruction_table.cpp",
        "evmone/lib/evmone/vm.cpp",
    }, &cppflags);

    evmone.addIncludePath(LazyPath{ .path = "evmone/evmc/include" });
    evmone.addIncludePath(LazyPath{ .path = "evmone/include" });
    evmone.addIncludePath(LazyPath{ .path = "intx/include" });
    evmone.addIncludePath(LazyPath{ .path = "ethash/include" });
    evmone.defineCMacro("PROJECT_VERSION", "\"0.11.0-dev\"");
    evmone.linkLibC();
    evmone.linkLibCpp();
    b.installArtifact(evmone);

    const exe = b.addExecutable(.{
        .name = "phant",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.addIncludePath(LazyPath{ .path = "evmone/include/evmone" });
    exe.addIncludePath(LazyPath{ .path = "evmone/evmc/include" });
    if (target.getCpuArch() == .x86_64) {
        // On x86_64, some functions are missing from the static library,
        // so we define dummy functions to make sure that it compiles.
        exe.addCSourceFile(.{
            .file = .{ .path = "src/glue.c" },
            .flags = &cflags,
        });
    }
    exe.linkLibrary(ethash);
    exe.linkLibrary(evmone);
    exe.linkLibC();
    exe.addModule("zig-rlp", mod_rlp);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const unit_tests = b.addTest(.{
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    unit_tests.addIncludePath(LazyPath{ .path = "evmone/include/evmone" });
    unit_tests.addIncludePath(LazyPath{ .path = "evmone/evmc/include" });
    if (target.getCpuArch() == .x86_64) {
        // On x86_64, some functions are missing from the static library,
        // so we define dummy functions to make sure that it compiles.
        unit_tests.addCSourceFile(.{
            .file = .{ .path = "src/glue.c" },
            .flags = &cflags,
        });
    }
    unit_tests.linkLibrary(ethash);
    unit_tests.linkLibrary(evmone);
    unit_tests.linkLibC();
    unit_tests.addModule("zig-rlp", mod_rlp);

    const run_unit_tests = b.addRunArtifact(unit_tests);
    run_unit_tests.has_side_effects = true;

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
