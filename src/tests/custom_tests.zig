const std = @import("std");
const config = @import("../config/config.zig");
const common = @import("../common/common.zig");
const vm = @import("../blockchain/vm.zig");
const state = @import("../state/state.zig");
const blockchain = @import("../blockchain/blockchain.zig");
const blockchain_types = @import("../blockchain/types.zig");
const Message = blockchain_types.Message;
const Environment = blockchain_types.Environment;
const types = @import("../types/types.zig");
const Hash32 = types.Hash32;
const Address = types.Address;
const StateDB = state.StateDB;
const ChainID = config.ChainId;
const Fork = blockchain.Fork;

test "create contract" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const coinbase = common.hexToAddress("0x1000000000000000000000000000000000000001");
    const coinbase_state = try state.AccountState.init(allocator, coinbase, 1, 0, &[_]u8{});
    var sdb = try StateDB.init(allocator, &[_]state.AccountState{coinbase_state});
    defer sdb.deinit();

    // Configure an EVM execution enviroment for a block from this coinbase.
    const env: Environment = .{
        .fork = try Fork.base.newBaseFork(allocator),
        .origin = coinbase,
        .coinbase = coinbase,
        .number = 100,
        .base_fee_per_gas = 1,
        .gas_limit = 15_000_000,
        .gas_price = 100,
        .time = 100,
        .prev_randao = [_]u8{42} ** 32,
        .state = &sdb,
        .chain_id = ChainID.SpecTest,
    };

    var vmi = vm.VM.init(std.testing.allocator, env);
    defer vmi.deinit();

    // Create contract.
    const contract_addr: Address = blk: {
        const msg: Message = .{
            .sender = coinbase,
            .target = null,
            .value = 0,
            .data = &[_]u8{
                // Init
                0x60, 0x8, // PUSH1 8
                0x60, 0x0C, // PUSH 12
                0x60, 0x00, // PUSH1 0
                0x39, // CODECOPY
                0x60, 0x8, // PUSH1 8
                0x60, 0x00, // PUSH1 0
                0xF3, // Return
                // Runtime code
                0x60, 0x01, // PUSH1 2 - Push 2 on the stack
                0x60, 0x02, // PUSH1 4 - Push 4 on the stack
                0x01, // ADD - Add stack[0] to stack[1]
                0x60, 0x00, // PUSH1 0
                0x55, // SSTORE
            },
            .gas = 10_000,
        };

        try sdb.startTx();
        const out = try vmi.processMessageCall(msg);

        // Check the contract creation execution was successful.
        try std.testing.expect(out.success);

        break :blk try common.computeCREATEContractAddress(allocator, coinbase, 1);
    };

    // Run it.
    {
        const msg: Message = .{
            .sender = coinbase,
            .target = contract_addr,
            .value = 0,
            .data = &[_]u8{},
            .gas = 100_000,
        };

        try sdb.startTx();
        const out = try vmi.processMessageCall(msg);

        // Check that the execution didn't fail, thus the contract was found and executed correctly.
        try std.testing.expect(out.success);
    }
}
