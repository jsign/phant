const std = @import("std");

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

pub fn build(b: *std.Build) void {
    // Generate src/version.zig
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const version = extractVersionFromZon(allocator) catch "unknown";
    const git_rev = gitRevision(b);

    var version_file = std.fs.cwd().createFile("src/version.zig", .{}) catch @panic("cannot create version.zig");
    defer version_file.close();
    version_file.writeAll(b.fmt(
        \\pub const release = "{s}";
        \\pub const revision = "{s}";
        \\pub const version = release ++ "+" ++ revision;
    , .{ version, git_rev })) catch @panic("cannot write version.zig");

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
            "delegation.cpp",
            "instructions_calls.cpp",
            "instructions_storage.cpp",
            "tracing.cpp",
            "vm.cpp",
        },
        .flags = &.{ "-std=c++20", "-fno-exceptions", "-fno-rtti", "-Wno-unknown-attributes", "-DPROJECT_VERSION=\"0.18.0\"" },
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
    evmone_mod.addIncludePath(b.path("evmone/lib")); // for evmone_precompiles/
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

    // Fetch test fixtures from ethereum/execution-spec-tests releases.
    // Downloads the tarball and extracts blockchain_tests/ into src/tests/fixtures/.
    const fixtures_url = "https://github.com/ethereum/execution-spec-tests/releases/download/v5.4.0/fixtures_stable.tar.gz";
    const fixtures_dir = "src/tests/fixtures";

    const fetch_fixtures = b.addSystemCommand(&.{
        "sh", "-c",
        // Only download if the directory doesn't already exist (or is empty)
        "if [ -d '" ++ fixtures_dir ++ "' ] && [ \"$(ls -A '" ++ fixtures_dir ++ "' 2>/dev/null)\" ]; then " ++
            "echo 'Fixtures already present, skipping download.'; " ++
            "else " ++
            "echo 'Downloading test fixtures...'; " ++
            "mkdir -p '" ++ fixtures_dir ++ "' && " ++
            "curl -sL '" ++ fixtures_url ++ "' | " ++
            "tar xz --strip-components=2 -C '" ++ fixtures_dir ++ "' " ++
            "'fixtures/blockchain_tests/shanghai' " ++
            "'fixtures/blockchain_tests/cancun'; " ++
            "echo \"Extracted $(find '" ++ fixtures_dir ++ "' -name '*.json' | wc -l) test fixture files.\"; " ++
            "fi",
    });
    fetch_fixtures.has_side_effects = true;

    const fetch_step = b.step("fetch-fixtures", "Download blockchain test fixtures from ethereum/execution-spec-tests");
    fetch_step.dependOn(&fetch_fixtures.step);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&fetch_fixtures.step);
    test_step.dependOn(&run_unit_tests.step);
}
