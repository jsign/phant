const std = @import("std");
const lib = @import("lib");
const custom = @import("./custom_tests.zig");
const spec = @import("./spec_tests.zig");

test "tests" {
    std.testing.log_level = .debug;
    // XXX this is commented out because of an apparent bug in zig 0.14.1
    // std.testing.refAllDeclsRecursive(lib.state);
    std.testing.refAllDeclsRecursive(custom);
    std.testing.refAllDeclsRecursive(spec);
}
