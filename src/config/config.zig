pub const ChainId = enum(u64) {
    SpecTest = 0,
    Mainnet = 1,
    Goerli = 5,
    Holesky = 17000,
    Kaustinen = 69420,
    Sepolia = 11155111,
};

pub const Config = struct {
    engine_port: u16 = 8551,
    network_id: u64 = @intFromEnum(ChainId.Mainnet),
};