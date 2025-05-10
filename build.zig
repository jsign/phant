const std = @import("std");
const LazyPath = std.Build.LazyPath;

// extract version string from build.zig.zon. The zon parser hasn't been merged
// into the std yet as of zig 0.13.0.
fn extractVersionFromZon(allocator: std.mem.Allocator) ![]const u8 {
    const version_field_decl = ".version = \"";
    var build_zon_file = try std.fs.cwd().openFile("build.zig.zon", .{});
    const build_zon_stat = try build_zon_file.stat();
    const build_zon = try build_zon_file.readToEndAlloc(allocator, build_zon_stat.size);
    const version_start = std.mem.indexOf(u8, build_zon, version_field_decl);
    if (version_start == null) {
        return error.CantFindVersionFieldStart;
    }
    const version_offset = version_start.? + version_field_decl.len;
    const version_end = std.mem.indexOf(u8, build_zon[version_offset..], "\"");
    if (version_end == null) {
        return error.CantFindVersionFieldEnd;
    }
    return build_zon[version_offset .. version_offset + version_end.?];
}

fn gitRevision(b: *std.Build) []const u8 {
    var returncode: u8 = undefined;
    const git_run = b.runAllowFail(&[_][]const u8{
        "git",
        "rev-parse",
        "--short",
        "HEAD",
    }, &returncode, .Ignore) catch v: {
        break :v "unstable";
    };
    return std.mem.trim(u8, git_run, " \t\n\r");
}

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) !void {
    const version_file_path = "src/version.zig";

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const version = try extractVersionFromZon(allocator);

    var version_file = try std.fs.cwd().createFile(version_file_path, .{});
    defer version_file.close();

    const git_rev = gitRevision(b);

    try version_file.writeAll(b.fmt(
        \\pub const release = "{s}";
        \\pub const revision = "{s}";
        \\pub const version = release ++ "+" ++ revision;
    , .{ version, git_rev }));

    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const dep_rlp = b.dependency("rlp", .{ .target = target, .optimize = optimize });
    const depSecp256k1 = b.dependency("zig_eth_secp256k1", .{ .target = target, .optimize = optimize });
    const mod_secp256k1 = depSecp256k1.module("zig-eth-secp256k1");
    const httpz = b.dependency("httpz", .{
        .target = target,
        .optimize = optimize,
    });
    const mod_httpz = httpz.module("httpz");

    const evmone_cmake_config_step = b.addSystemCommand(&.{ "cmake", "-S", "evmone", "-B", "zig-out/evmone_build" });
    const evmone_cmake_build_step = b.addSystemCommand(&.{ "cmake", "--build", "zig-out/evmone_build" });
    evmone_cmake_build_step.step.dependOn(&evmone_cmake_config_step.step);

    const zigcli = b.dependency("zigcli", .{});

    const exe = b.addExecutable(.{
        .name = "phant",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe.addIncludePath(b.path("evmone/include/evmone"));
    exe.addIncludePath(b.path("evmone/evmc/include"));
    exe.addLibraryPath(b.path("zig-out/evmone_build/lib"));
    exe.linkSystemLibrary("evmone");
    // exe.linkCxxAbi();
    exe.linkLibC();
    exe.root_module.addImport("zig-rlp", dep_rlp.module("zig-rlp"));
    exe.linkLibrary(depSecp256k1.artifact("secp256k1"));
    exe.root_module.addImport("zig-eth-secp256k1", mod_secp256k1);
    exe.root_module.addImport("httpz", mod_httpz);
    exe.root_module.addImport("simargs", zigcli.module("simargs"));
    exe.root_module.addImport("pretty-table", zigcli.module("pretty-table"));
    exe.step.dependOn(&evmone_cmake_build_step.step);

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
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.addLibraryPath(b.path("zig-out/evmone_build/lib"));
    unit_tests.linkSystemLibrary("evmone");
    // exe.linkCxxAbi();
    unit_tests.linkLibC();
    unit_tests.linkLibC();
    unit_tests.addIncludePath(b.path("evmone/include/evmone"));
    unit_tests.addIncludePath(b.path("evmone/evmc/include"));
    unit_tests.root_module.addImport("zig-rlp", dep_rlp.module("zig-rlp"));
    unit_tests.linkLibrary(depSecp256k1.artifact("secp256k1"));
    unit_tests.root_module.addImport("zig-eth-secp256k1", mod_secp256k1);
    unit_tests.root_module.addImport("pretty-table", zigcli.module("pretty-table"));

    const run_unit_tests = b.addRunArtifact(unit_tests);
    run_unit_tests.has_side_effects = true;

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
