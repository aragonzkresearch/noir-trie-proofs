# noir-trie-proofs

## Description

This library contains primitives necessary for

- RLP decoding in the form of look-up table construction
- Ethereum state and storage proof verification (or verification of any trie proof involving 32-byte long keys)

## Consuming this library

With Nargo v0.10.4, you can depend on this library by adding the following to your `Nargo.toml`:

```toml
[dependencies]
noir_trie_proofs = { git = "aragonzkresearch/noir-trie-proofs", tag = "main", directory = "lib" }
```

## Contributing

To run the unit tests, you can run `nargo test` in the project root.

To run the integration tests, you can execute against various projects in `tests/`:

- `nargo execute --package depth_8_state_proof`
- `nargo execute --package depth_8_storage_proof`
- `nargo execute --package one_level`
- `nargo execute --package rlp_decode`
