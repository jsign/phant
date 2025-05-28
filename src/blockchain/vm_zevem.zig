const zevem = @import("zevem");
const std = @import("std");
const lib = @import("lib");
const common = lib.common;
const Allocator = std.mem.Allocator;
const Environment = lib.blockchain_types.Environment;
const Message = lib.blockchain_types.Message;

const empty_hash = common.comptimeHexToBytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

const EnvFuncs = struct {};
const EVM = zevem.evm.New(EnvFuncs);

pub const VM = struct {
    const vmlog = std.log.scoped(.vm);

    allocator: Allocator,
    env: Environment,
    envfuncs: *EnvFuncs,
    evm: EVM,

    // init creates a new EVM VM instance. The caller must call deinit() when done.
    pub fn init(allocator: Allocator, env: Environment) VM {
        const envfuncs = allocator.create(EnvFuncs) catch @panic("error allocating environment function");
        const evm = EVM.init(allocator, envfuncs) catch @panic("error in evm init");
        return .{
            .allocator = allocator,
            .env = env,
            .evm = evm,
            .envfuncs = envfuncs,
        };
    }

    // deinit destroys a VM instance.
    pub fn deinit(self: *VM) void {
        if (self.evm.*.destroy) |destroy| {
            destroy(self.evm);
        }
        self.allocator.destroy(self.envfuncs);
    }

    // processMessageCall executes a message call.
    pub fn processMessageCall(self: *VM, msg: Message) !MessageCallOutput {
        if (msg.target != null) {
            try self.env.state.incrementNonce(msg.sender);
        }

        try self.evm.execute();
        return .{
            .gas_left = 0,
            .refund_counter = 0,
            .success = true,
        };
    }
};

pub const MessageCallOutput = struct {
    success: bool,
    gas_left: u64,
    refund_counter: u64,
    // logs: Union[Tuple[()], Tuple[Log, ...]] TODO
    // accounts_to_delete: AddressKeySet, // TODO (delete?)
};
