// Raw types.
pub const Hash32 = [32]u8;
pub const Bytes32 = [32]u8;
pub const Bytes31 = [31]u8;

// Ethereum execution layer types.
pub const Address = [20]u8;

// Bloom
pub const LogsBloom = [256]u8;

// Blocks
const block = @import("block.zig");
pub const empty_uncle_hash = block.empty_uncle_hash;
pub const Block = block.Block;
pub const BlockHeader = block.BlockHeader;
pub const Withdrawal = @import("withdrawal.zig").Withdrawal;

// Receipt & Logs
const receipt = @import("receipt.zig");
pub const Receipt = receipt.Receipt;
pub const Log = receipt.Log;
pub const LogsBloom = [256]u8;

// Transactions
const transaction = @import("transaction.zig");
pub const AccessListTuple = transaction.AccessListTuple;
pub const Tx = transaction.Tx;
pub const TxTypes = transaction.TxTypes;
pub const LegacyTx = transaction.LegacyTx;
pub const AccessListTx = transaction.AccessListTx;
pub const MarketFeeTx = transaction.FeeMarketTx;
