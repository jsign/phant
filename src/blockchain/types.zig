const types = @import("../types/types.zig");
const config = @import("../config/config.zig");
const common = @import("../common/common.zig");
const StateDB = @import("../state/statedb.zig").StateDB;
const Address = types.Address;
const Hash32 = types.Hash32;
const Bytes32 = types.Bytes32;
const AddressSet = common.AddressSet;
const AddresssKey = common.AddressKey;
const AddressKeySet = common.AddressKeySet;

pub const Environment = struct {
    caller: Address,
    block_hashes: [256]Hash32,
    origin: Address,
    coinbase: Address,
    number: u64,
    base_fee_per_gas: u256,
    gas_limit: u64,
    gas_price: u256,
    time: u64,
    prev_randao: Bytes32,
    state: *StateDB,
    chain_id: config.ChainId,
};

pub const Message = struct {
    caller: Address,
    target: ?Address,
    current_target: Address,
    gas: u64,
    value: u256,
    data: []const u8,
    code_address: ?Address,
    code: []const u8,
    accessed_addresses: AddressSet,
    accessed_storage_keys: AddressKeySet,

    pub fn deinit(self: *Message) void {
        self.accessed_addresses.deinit();
        self.accessed_addresses = undefined;
        self.accessed_storage_keys.deinit();
        self.accessed_storage_keys = undefined;
    }
};
