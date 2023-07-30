# phant

An experimental Zig Ethereum client.

## Setup

This repo is very experimental, so you have to do some things once.

For now, we use the [Zig master](https://ziglang.org/download/) compiler version.
As soon as v0.11.0 is released (in some weeks), we'll try to stick v0.11.X versions instead.

### Initialize git submodules (temporary)
After pulling this repo for the first time, do:
1. `git submodule init`
2. `git submodule update -v`

This is temporary until we use Zig's package manager for a better UX.

### Install EVMOne shared library (temporary)

You can do: 
- `sudo cp ./evmone/libevmone.so.0.10 /usr/lib`

If you don't trust (which is a good idea in general) the shared library provided in this repo, you can download it from the [EVMOne releases assets](https://github.com/ethereum/evmone/releases).

This is a temporary requirement, ideally, we'd like to:
1. Compile EVMOne in the `build.zig` using the Zig C++ compiler.
2. Compile it as a shared object instead of a shared library, so it could be statically linked.

## Run

You can run _something_ here with:
- `zig build run`: which runs `main.zig`, which is a simple playground for phant-EVMOne intregration.
- `zig build test`: it attempts to run a particular [exec-spec-tests](https://github.com/ethereum/execution-spec-tests) fixture `exec-spec/tests/fixtures/exec-spec/fixture.json`, which is an official spec test fixture. This does a bunch of decoding into EVM types, creates a `statedb` with pre-state (and post-state for posterior check), and tries to execute the block transactions.

Now, everything is quite messy until we have a passing test for this official exec-spec-test fixture.

Probably after that, we can refactor a bit the code to create proper modules and define some clear path forward in each module.

## License

MIT

