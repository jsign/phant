const std = @import("std");
const types = @import("../types/types.zig");
const Address = types.Address;

pub const gas_limit_adjustement_factor = 1024;
pub const gas_limit_minimum = 5000;
pub const gas_init_code_word_const = 2;

pub const tx_base_cost = 21000;
pub const tx_data_cost_per_zero = 4;
pub const tx_data_cost_per_non_zero = 16;
pub const tx_create_cost = 32000;
pub const tx_access_list_address_cost = 2400;
pub const tx_access_list_storage_key_cost = 1900;

pub const base_fee_max_change_denominator = 8;
pub const elasticity_multiplier = 2;
pub const max_code_size = 0x6000;

pub const precompiled_contract_addresses = [_]Address{
    addressFromInt(1), // ECRECOVER
    addressFromInt(2), // SHA256
    addressFromInt(3), // RIPEMD160
    addressFromInt(4), // IDENTITY_ADDRESS
    addressFromInt(5), // MODEXP_ADDRESS
    addressFromInt(6), // ALT_BN128_ADD
    addressFromInt(7), // ALT_BN128_MUL
    addressFromInt(8), // ALT_BN128_PAIRING_CHECK
    addressFromInt(9), // BLAKE2F
};

fn addressFromInt(comptime i: u160) Address {
    var addr: Address = undefined;
    std.mem.writeInt(u160, &addr, i, .Big);
    return addr;
}
