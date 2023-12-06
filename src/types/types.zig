// Raw types.
pub const Hash32 = [32]u8;
pub const Bytes32 = [32]u8;
pub const Bytes31 = [31]u8;

// Ethereum execution layer types.
pub const Bytecode = []const u8;
pub const Address = [20]u8;

// State.
pub const AccountState = @import("account_state.zig");

// Blocks
pub const Block = @import("block.zig").Block;
pub const BlockHeader = @import("block.zig").Header;
pub const Withdrawal = @import("withdrawal.zig");

pub const empty_uncle_hash = @import("block.zig").empty_uncle_hash;

// Transactions
const transaction = @import("transaction.zig");
pub const SignatureValues = transaction.SignatureValues;
pub const Txn = transaction.Txn;
pub const TxnTypes = transaction.TxnTypes;
pub const LegacyTxn = transaction.LegacyTxn;
pub const AccessListTxn = transaction.AccessListTxn;
pub const MarketFeeTxn = transaction.MarketFeeTxn;
