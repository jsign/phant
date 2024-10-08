const std = @import("std");
const types = @import("../types/types.zig");
const hexutils = @import("hexutils.zig");
const rlp = @import("rlp.zig");
const contract = @import("contract.zig");

// Hex
pub const prefixedhex2hash = hexutils.prefixedhex2hash;
pub const prefixedhex2byteslice = hexutils.prefixedhex2byteslice;
pub const prefixedHexToInt = hexutils.prefixedHexToInt;
pub const hexToAddress = hexutils.hexToAddress;
pub const comptimeHexToBytes = hexutils.comptimeHexToBytes;

// Sets
pub const AddressSet = std.AutoHashMap(types.Address, void);
pub const AddressKey = struct { address: types.Address, key: types.Bytes32 };
pub const AddressKeySet = std.AutoHashMap(AddressKey, void);

// RLP
pub const decodeRLP = rlp.decodeRLP;
pub const encodeToRLPAndHash = rlp.encodeToRLPAndHash;

// Address
pub const computeCREATEContractAddress = contract.computeCREATEContractAddress;
pub const computeCREATE2ContractAddress = contract.computeCREATE2ContractAddress;
