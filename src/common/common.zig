const std = @import("std");
const types = @import("../types/types.zig");
const hexutils = @import("./hexutils.zig");

pub const prefixedhex2hash = hexutils.prefixedhex2hash;
pub const prefixedhex2byteslice = hexutils.prefixedhex2byteslice;
pub const prefixedhex2u64 = hexutils.prefixedhex2u64;
pub const hexToAddress = hexutils.hexToAddress;
pub const comptimeHexToBytes = hexutils.comptimeHexToBytes;

pub const AddressSet = std.HashMap(types.Address, void);

pub const AddressKey = struct { address: types.Address, key: types.Bytes32 };
pub const AddressKeySet = std.HashMap(AddressKey, void);
