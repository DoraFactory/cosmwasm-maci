# CosmWasm Maci Contract
This is maci cosmwasm contract.

### Maci Support

- Related `circuits` and offchain js scripts from: https://github.com/dorahacksglobal/qf-maci.

## cw-groth16
This cosmwasm contract verifies Groth16 proofs, using the previously developed [SnarkJS-Bellman Adapter](https://github.com/DoraFactory/snarkjs-bellman-adapter).

### Environment:
- OS: Mac M1
- Rust version: stable-aarch64-apple-darwin (default)  rustc 1.69.0 (84c898d65 2023-04-16)

### Get Start

**1. Get code**

```bash
git clone https://github.com/DoraFactory/cosmwasm-maci
```



**2. About test code**

> In [test_all_round()](./src/tests.rs) we tested the entire maci process, with relevant test data from [qf-maci](https://github.com/dorahacksglobal/qf-maci).

```bash
cd cosmwasm-maci/maci
cargo test
```



**3. Compile contract**

Compile and Optimize the wasm code

> If you are using different os, you can change the docker image on your machine and run, otherwise you will compile failed.

If your system archtecture is `arm`,go into the `maci` dir and run with this command:

```bash
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/rust-optimizer-arm64:0.12.11
```

and then you will see an `artifacts` dir and next we will upload it to chain.

If your system archtecture is `amd`, run with this:

```bash
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/rust-optimizer:0.12.11
```
