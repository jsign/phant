const std = @import("std");
const lib = @import("lib");
const custom = @import("./custom_tests.zig");
const spec = @import("./spec_tests.zig");

test "tests" {
    std.testing.log_level = .debug;
    std.testing.refAllDecls(lib);
    std.testing.refAllDeclsRecursive(custom);
    std.testing.refAllDeclsRecursive(spec);
}
