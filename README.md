# phant

An experimental Zig Ethereum client.

## Setup

This repo is very experimental, so you have to do some things once.

We use the [Zig v0.13](https://ziglang.org/download/) compiler version.

### Initialize git submodules

After pulling this repo for the first time, do:

1. `git submodule init`
2. `git submodule update -v`

## Run

You can run _something_ here with:

- `zig build run`: which runs `main.zig`, which is a simple playground for phant-EVMOne intregration.
- `zig build test`: it attempts to run a particular [exec-spec-tests](https://github.com/ethereum/execution-spec-tests) fixture `exec-spec/tests/fixtures/exec-spec/fixture.json`, which is an official spec test fixture. This does a bunch of decoding into EVM types, creates a `statedb` with pre-state (and post-state for posterior check), and tries to execute the block transactions.

Now, everything is quite messy until we have a passing test for this official exec-spec-test fixture.

Probably after that, we can refactor a bit the code to create proper modules and define some clear path forward in each module.

## License

MIT
