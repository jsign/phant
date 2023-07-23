const std = @import("std");
const builtin = @import("builtin");
const test_allocator = std.testing.allocator;
const Allocator = std.mem.Allocator;
const ArrayHashMap = std.ArrayHashMap;
const fmtSliceHexLower = std.fmt.fmtSliceHexLower;

pub const Bytecode = []const u8;
pub const Address = [32]u8;

pub const AccountState = struct {
    const log = std.log.scoped(.account_state);

    account: Address,
    nonce: u256,
    balance: u256,
    code: Bytecode,
    storage: std.AutoHashMap(u256, u256),

    pub fn init(allocator: Allocator, account: Address, nonce: u256, balance: u256, code: Bytecode) AccountState {
        return AccountState{
            .account = account,
            .nonce = nonce,
            .balance = balance,
            .code = code,
            .storage = std.AutoHashMap(u256, u256).init(allocator),
        };
    }

    pub fn deinit(self: *AccountState) void {
        self.storage.deinit();
    }

    pub fn storage_get(self: *const AccountState, key: u256) ?u256 {
        self.log_debug("get storage key=0x{x}", .{key});
        return self.storage.get(key);
    }

    pub fn storage_set(self: *AccountState, key: u256, value: u256) !void {
        self.log_debug("set storage key=0x{x}, value=0x{x}", .{ key, value });
        try self.storage.put(key, value);
    }

    fn log_debug(self: *const AccountState, comptime str: []const u8, args: anytype) void {
        // TODO(jsign): add account printing.
        const fmt = "addr={s}...{s}, " ++ str;
        const acc_hex = std.fmt.bytesToHex(self.account, std.fmt.Case.lower);
        log.debug(fmt, .{ acc_hex[0..6], acc_hex[acc_hex.len - 6 ..] } ++ args);
    }
};

test "storage" {
    std.testing.log_level = .debug;

    var account = AccountState.init(test_allocator, undefined, 0, 0, &[_]u8{});
    defer account.deinit();

    // Set key=0x42, val=0x43, and check get.
    try account.storage_set(0x42, 0x43);
    try std.testing.expect(account.storage_get(0x42) == 0x43);

    // Get a key that doesn't exist.
    if (account.storage_get(0x44)) |_| {
        return error.ExpectedError;
    }

    // Set existing key=0x42 to new value and get.
    try account.storage_set(0x42, 0x13);
    try std.testing.expect(account.storage_get(0x42) == 0x13);
}
