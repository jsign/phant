const std = @import("std");
const types = @import("types.zig");
const crypto = @import("../crypto/crypto.zig");
const Allocator = std.mem.Allocator;
const hasher = crypto.hasher;
const Hash32 = types.Hash32;
const Address = types.Address;
const LogsBloom = types.LogsBloom;
const TxTypes = types.TxTypes;

pub const Receipt = struct {
    tx_type: TxTypes,

    succeeded: bool,
    cumulative_gas_used: u64,
    bloom: LogsBloom,
    logs: []Log,

    pub fn init(tx_type: TxTypes, succeeded: bool, cumulative_gas_used: u64, logs: []Log) Receipt {
        return Receipt{
            .tx_type = tx_type,
            .succeeded = succeeded,
            .cumulative_gas_used = cumulative_gas_used,
            .bloom = calculateLogsBloom(logs),
            .logs = logs,
        };
    }

    fn calculateLogsBloom(logs: []Log) LogsBloom {
        var logs_bloom = std.mem.zeroes(LogsBloom);

        for (logs) |log| {
            addToBloom(&logs_bloom, &log.address);
            for (log.topics) |topic| {
                addToBloom(&logs_bloom, &topic);
            }
        }

        return logs_bloom;
    }

    fn addToBloom(bloom: *LogsBloom, value: []const u8) void {
        const hash = hasher.keccak256(value);

        inline for (0..3) |i| {
            const hash_16bit_word = hash[i * 2 .. (i + 1) * 2].*;
            const bit_to_set = @as(u11, @intCast(std.mem.readInt(u16, &hash_16bit_word, std.builtin.Endian.Big) & 0x07FF));
            const bit_index = 0x07FF - bit_to_set;

            const byte_index = bit_index / 8;
            const bit_value = @as(u8, 1) << (7 - @as(u3, @intCast(bit_index % 8)));

            bloom[byte_index] |= bit_value;
        }
    }
};

pub const Log = struct {
    address: Address,
    topics: []Hash32,
    data: []u8,
};