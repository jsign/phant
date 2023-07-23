const std = @import("std");
const evmc = @cImport({
    @cInclude("evmc/evmc.h");
});
const evmone = @cImport({
    @cInclude("evmone.h");
});

pub fn newHost() evmc.struct_evmc_host_interface {
    return evmc.struct_evmc_host_interface{
        .account_exists = accountExists,
        .get_storage = getStorage,
        .set_storage = setStorage,
        .get_balance = getBalance,
        .get_code_size = getCodeSize,
        .get_code_hash = getCodeHash,
        .copy_code = copyCode,
        .selfdestruct = selfDestruct,
        .call = call,
        .get_tx_context = getTxContext,
        .get_block_hash = getBlockHash,
        .emit_log = emitLog,
        .access_account = accessAccount,
        .access_storage = accessStorage,
    };
}

fn getTxContext(ctx: ?*evmc.struct_evmc_host_context) callconv(.C) evmc.struct_evmc_tx_context {
    _ = ctx;
    @panic("TODO");
}

fn getBlockHash(ctx: ?*evmc.struct_evmc_host_context, xx: i64) callconv(.C) evmc.evmc_bytes32 {
    _ = xx;
    _ = ctx;
    @panic("TODO");
}

fn accountExists(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) bool {
    _ = addr;
    _ = ctx;
    @panic("TODO");
}

fn getStorage(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, dest: [*c]const evmc.evmc_bytes32) callconv(.C) evmc.evmc_bytes32 {
    _ = dest;
    _ = addr;
    _ = ctx;
    @panic("TODO");
}
fn setStorage(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, value: [*c]const evmc.evmc_bytes32, xxx: [*c]const evmc.evmc_bytes32) callconv(.C) evmc.enum_evmc_storage_status {
    _ = xxx;
    _ = value;
    _ = addr;
    _ = ctx;
    @panic("TODO");
}

fn getBalance(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) evmc.evmc_uint256be {
    _ = ctx;
    const addr_hex = std.fmt.bytesToHex(addr.*.bytes, std.fmt.Case.lower);
    std.debug.print("called getBalance(0x{s})\n", .{addr_hex});

    var beval: [32]u8 = undefined;
    std.mem.writeIntSliceBig(u256, &beval, 142);

    return evmc.evmc_uint256be{
        .bytes = beval,
    };
}

fn getCodeSize(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) usize {
    _ = addr;
    _ = ctx;
    @panic("TODO");
}
fn getCodeHash(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) evmc.evmc_bytes32 {
    _ = addr;
    _ = ctx;
    @panic("TODO");
}
fn copyCode(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, xxx: usize, xxy: [*c]u8, xxz: usize) callconv(.C) usize {
    _ = xxz;
    _ = xxy;
    _ = xxx;
    _ = addr;
    _ = ctx;
    @panic("TODO");
}
fn selfDestruct(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, addr2: [*c]const evmc.evmc_address) callconv(.C) bool {
    _ = addr2;
    _ = addr;
    _ = ctx;
    @panic("TODO");
}
fn emitLog(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, xxx: [*c]const u8, xxy: usize, xxz: [*c]const evmc.evmc_bytes32, xxxzz: usize) callconv(.C) void {
    _ = xxxzz;
    _ = xxz;
    _ = xxy;
    _ = xxx;
    _ = addr;
    _ = ctx;
    @panic("TODO");
}
fn accessAccount(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address) callconv(.C) evmc.enum_evmc_access_status {
    _ = ctx;
    const addr_hex = std.fmt.bytesToHex(addr.*.bytes, std.fmt.Case.lower);
    std.debug.print("host accessAccount(0x{s})\n", .{addr_hex});
    return evmc.EVMC_ACCESS_COLD;
}
fn accessStorage(ctx: ?*evmc.struct_evmc_host_context, addr: [*c]const evmc.evmc_address, value: [*c]const evmc.evmc_bytes32) callconv(.C) evmc.enum_evmc_access_status {
    _ = value;
    _ = addr;
    _ = ctx;
    @panic("TODO");
}
fn call(ctx: ?*evmc.struct_evmc_host_context, msg: [*c]const evmc.struct_evmc_message) callconv(.C) evmc.struct_evmc_result {
    _ = msg;
    _ = ctx;
    @panic("TODO");
}
