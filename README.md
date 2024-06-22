# phant

An experimental Zig Ethereum client.

## Setup

This repo is very experimental, so you have to do some things once.

We use the [Zig v0.13](https://ziglang.org/download/) compiler version.

### Initialize git submodules

After pulling this repo for the first time, do:

1. `git submodule init`
2. `git submodule update -v`

## Running tests

You can run _something_ here with:

- `zig build test`: it attempts to run a particular [exec-spec-tests](https://github.com/ethereum/execution-spec-tests) fixture `exec-spec/tests/fixtures/exec-spec/fixture.json`, which is an official spec test fixture. This does a bunch of decoding into EVM types, creates a `statedb` with pre-state (and post-state for posterior check), and tries to execute the block transactions.

Now, everything is quite messy until we have a passing test for this official exec-spec-test fixture.

Probably after that, we can refactor a bit the code to create proper modules and define some clear path forward in each module.

## Running the client

To run the (wip) client, type

```
zig build run
```

By default, the network is mainnet. You can run the sepolia chain configuration by using the `network_id` option:

```
zig build run -- --network_id Sepolia
```

Any other network requires its own _chainspec_ file. You can run a custom chainspec by using the `chainspec` option:

```
zig build run -- --chainspec <path to chainspec>.json
```

## License

MIT
