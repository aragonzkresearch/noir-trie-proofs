# noir-trie-proofs
## Description
This library contains primitives necessary for

- RLP decoding in the form of look-up table construction
- Ethereum state and storage proof verification (or verification of any trie proof involving 32-byte long keys)

## Example Usage
### RLP decoding
### Trie proofs

A Rust program that fetches account and storage proofs as well as the appopriate root hash for a given block number via JSON RPC and appropriately serialises it for use with the `verify_proof32` function is provided under `noir-trie-proof-helper`. This data is written to stdout. 

For example, to obtain a proof for storage slot 0x? of the contract at address `0xb47e3cd837dDF8e4c57f05d70ab865de6e193bbb` at block number `14194126`, run

```
noir-trie-proof-fetch --storage-proof --max-depth 8 --slot 0x? --address 0xb47e3cd837dDF8e4c57f05d70ab865de6e193bbb --json-rpc https://rpc.ankr.com/eth
```

Similarly, to obtain an account proof for address ... at block number ..., run

```
noir-trie-proof-fetch --account-proof --max-depth 8 --address ... --json-rps https://rpc.ankr.com/eth
```

Due to the nature of ZK programs, a maximum depth *must* be specified, since the exact size of circuit input data must be known at compile time.
