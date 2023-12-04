const ethash = @cImport({
    @cInclude("ethash/keccak.h");
});

pub fn keccak256(data: []const u8) [32]u8 {
    const ret = ethash.ethash_keccak256(data.ptr, data.len);
    return ret.bytes;
}
