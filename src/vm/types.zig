const std = @import("std");
const builtin = @import("builtin");
const test_allocator = std.testing.allocator;
const Allocator = std.mem.Allocator;
const ArrayHashMap = std.ArrayHashMap;
const fmtSliceHexLower = std.fmt.fmtSliceHexLower;
const util = @import("../util/util.zig");

pub const Bytecode = []const u8;
pub const Address = [20]u8;

// TODO(jsign): switch to union?
pub const Transaction = struct {
    type: u8,
    chain_id: u256,
    nonce: u64,
    gas_price: u256,
    value: u256,
    to: ?Address,
    data: []const u8,
    gas_limit: u64,

    // TODO(jsign): comment about data ownership.
    pub fn init(type_: u8, chain_id: u256, nonce: u64, gas_price: u256, value: u256, to: ?Address, data: []const u8, gas_limit: u64) Transaction {
        return Transaction{
            .type = type_,
            .chain_id = chain_id,
            .nonce = nonce,
            .gas_price = gas_price,
            .value = value,
            .to = to,
            .data = data,
            .gas_limit = gas_limit,
        };
    }

    // TODO(jsign): use some secp256k1 library.
    pub fn get_from(_: *const Transaction) Address {
        const from: Address = comptime blk: {
            var buf: Address = undefined;
            _ = std.fmt.hexToBytes(&buf, "a94f5374Fce5edBC8E2a8697C15331677e6EbF0B") catch unreachable;
            break :blk buf;
        };
        return from;
    }

    // TODO(jsign): add helper to get txn hash.
};

pub const AccountState = struct {
    const log = std.log.scoped(.account_state);

    addr: Address,
    nonce: u256,
    balance: u256,
    code: Bytecode,
    storage: std.AutoHashMap(u256, u256),

    // init initializes an account state with the given values.
    // The bytecode slice isn't owned by the account state, so it must outlive the account state.
    // deinit() must be called on the account state to free the storage.
    //
    // TODO(jsign): consider copying code to make it less brittle, or clarify in comment.
    pub fn init(allocator: Allocator, addr: Address, nonce: u256, balance: u256, code: Bytecode) AccountState {
        return AccountState{
            .addr = addr,
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
        const acc_hex = std.fmt.bytesToHex(self.addr, std.fmt.Case.lower);
        log.debug(fmt, .{ acc_hex[0..6], acc_hex[acc_hex.len - 6 ..] } ++ args);
    }
};

test "storage" {
    var account = AccountState.init(test_allocator, util.hex_to_address("0x010142"), 0, 0, &[_]u8{});
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
