# noir-trie-proofs

## Description

This repository contains Noir primitives necessary for

- RLP decoding in the form of look-up table construction
- Ethereum state and storage proof verification (or verification of any trie proof involving 32-byte long keys)

A Rust crate is also provided for the purpose of data preprocessing and reproducibility of some of the examples provided (cf. [Rust component](#rust-component)).

The following subsections elaborate on potential use-cases, which are centred around RLP list decoding and storage and state trie proof verification. Though the methods here do not cover other interesting trie proof verification use-cases, e.g. the case of variable key length, the building blocks are provided. For more information, consult `lib/src/rlp.nr` and `lib/src/lib.nr`.

### RLP decoding
#### Constants
- `MAX_LEN_IN_BYTES` represents the maximum permissible byte length of the length of an RLP payload and is set to 2. This is required for technical reasons and implies that the decoding functions below are only applicable to payloads of byte length less than `2^16`.
- `STRING` and `LIST` form an enum representing the string and list type respectively.
#### Types
To streamline RLP decoding, two types are provided:
- `RLP_Header` represents an RLP header and has fields for the offset of the RLP payload (`offset: Field`), the byte length of the payload (`length: Field`) and the data type of the payload (`data_type: Field`), i.e. whether the payload represents a sequence of bytes (`STRING`) or a list of elements (`LIST`), i.e. the concatenation of RLP-encoded bytes.
- `RLP_List<NUM_FIELDS>` represents a decoded RLP list in the form of a look-up table. It has fields for the offsets of the elements of this list (`offset: [Field; NUM_FIELDS]`), their byte lengths (`length: [Field; NUM_FIELDS]`), their data types (`data_type: [Field; NUM_FIELDS]`) and the number of elements in the list (`num_fields: Field`). `NUM_FIELDS` should be chosen large enough so that `num_fields <= NUM_FIELDS`.

#### Associated functions
- `fn decode0<N>(input: [u8; N]) -> (Field, Field)` takes an RLP-encoded string as input and returns the offset of the byte string and its length.
- `fn decode1<N, NUM_FIELDS>(input: [u8; N]) -> RLP_List<NUM_FIELDS>` takes an RLP-encoded list as input and returns a decoded RLP list struct as described above. Note that a type annotation is required when invoking `decode1`, e.g.
```rust
	let decoded_bytes: RLP_List<NUM_FIELDS> = decode1(input);
```
- `fn decode1_small_lis<N, NUM_FIELDS>(input: [u8; N]) -> RLP_List<NUM_FIELDS>` is the same as `decode1` except it assumes that the list elements are strings of length less than 56 bytes. This is sufficient e.g. in the case of storage trie nodes or non-terminal state trie nodes and is provided for gate count optimisation purposes.

### Trie proof verification
#### Constants
- `HASH_LENGTH` is the length of a key after hashing, i.e. 32.
- `HASH_NIBBLE_LENGTH` is the length of a key expressed as a series of nibbles after hashing, i.e. 64.
- `MAX_TRIE_NODE_LENGTH` is the maximum number of bytes in a trie node under the assumption of 32-byte long keys.
- `MAX_STORAGE_VALUE_LENGTH` is the maximum number of bytes in a storage slot, i.e. 32.
- `MAX_ACCOUNT_STATE_LENGTH` is the maximum number of bytes in an account state, i.e. the maximum number of bytes in the value slot of the terminal node of a state proof.
- `MAX_NUM_FIELDS` is the maximum number of RLP-encoded elements in a trie node, i.e. 17.
- `EXTENSION` and `LEAF` form an enum representing the extension and leaf types for 2-nodes.

#### Types
- `TrieProof<KEY_LEN, PROOF_LEN, MAX_VALUE_LEN>` represents a trie proof whose key is`KEY_LEN` bytes long and whose value and proof lengths are at most `MAX_VALUE_LEN` and `PROOF_LEN` bytes long respectively. It has fields for the key (`key: [u8; KEY_LEN]`), value (`value: [u8; MAX_VALUE_LEN]`), proof path (`proof: [u8; PROOF_LEN]`) and depth (`depth: Field`). For technical reasons, the methods described below assume that `PROOF_LEN` is a multiple of `MAX_TRIE_NODE_LENGTH` and that nodes in the trie proof are right-padded with zeros and subsequently concatenated in order to form the proof path array. See [Preprocessing](#preprocessing) below for further details. 

  For storage proofs, the relevant type is `TrieProof<32, PROOF_LEN, MAX_VALUE_LEN>` and for state proofs it is `TrieProof<20, PROOF_LEN, MAX_VALUE_LEN>`. Note that for the latter, even though we think of the keys as being 20 bytes long, the trie itself takes the `keccak256`-hashed key as input, i.e. a 32-byte key is resolved, which is taken care of under the hood in the following methods.

- `StorageProof<PROOF_LEN>` is a type alias for `TrieProof<32, PROOF_LEN, MAX_STORAGE_VALUE_LENGTH>`.
- `StateProof<PROOF_LEN>` is a type alias for `TrieProof<20, PROOF_LEN, MAX_ACCOUNT_STATE_LENGTH>`.

#### Methods
- `fn verify_storage_root(self: TrieProof<32, PROOF_LEN, MAX_VALUE_LEN>, storage_root: [u8; HASH_LENGTH]) -> bool`  takes a storage proof (`self`) and storage root (`storage_root`) as inputs and returns `true` if the proof is successfully verified. `PROOF_LEN` is subject to the restrictions explained above and `MAX_VALUE_LEN <= 32` should be large enough to encapsulate the value that the key resolves to in the proof, which is encoded as a big-endian byte array.
- `fn verify_state_root(self: TrieProof<20, PROOF_LEN, MAX_VALUE_LEN>, state_root: [u8; HASH_LENGTH]) -> bool` takes a state proof (`self`) and state root (`state_root`) as inputs and returns `true` if the proof is successfully verified. `PROOF_LEN` is as before, and `MAX_VALUE_LEN <= MAX_ACCOUNT_STATE_LENGTH` should be large enough to encapsulate the value the key resolves to in the proof, which is the RLP-encoded account state associated with the address given by `self.key`.

#### Examples
Besides the unit tests, the following examples are provided as integration tests:
- `tests/depth_8_state_proof` verifies a private state proof of depth 8 with public input given by the state root.
- `tests/depth_8_storage_proof` verifies a private state proof of depth less than 8 with public input given by the storage root.
- `tests/one_level` illustrates one step through a storage proof by taking a node, a key and a pointer to the current offset (in nibbles) to extract the hash of the following node as well as a pointer to the next nibble to be resolved.
- `tests/rlp_decode` illustrates RLP decoding.

#### Preprocessing

As remarked above, trie proofs must be appropriately padded and flattened for use in circuits. Concretely, if trie proofs are expressed as a list of lists of 8-bit words, the preprocessing required may be expressed by the following mapping (constants as above modulo capitalisation):

```haskell
pad :: [[Word8]] -> [Word8]
pad xs = concat
         $ map (\x -> x ++ byte_padding x)
         $ xs ++ depth_padding
  where
    byte_padding node = replicate (max_trie_node_length - length node) 0
    depth_padding = replicate (max_depth - length xs) []
```

Moreover, the values that trie proofs terminate in are assumed to be in a byte array left-padded with zeros to the maximum size of the slot they are stored in, i.e. if `max_len` denotes the maximum possible length of a value, then the mapping to be applied is given as follows:

```haskell
left_pad :: [Word8] -> Int -> [Word8]
left_pad xs max_len = (replicate (max_len - length xs) 0) ++ xs
```

## Rust component
For convenience, we provide Rust code in the form of a library-and-binary crate. The library contains helper functions for fetching state and storage proofs via JSON RPC as well as applying the steps outlined in [Preprocessing](#preprocessing), while the binary calls these helper functions and dumps the results to standard output in Toml form. The binary may be used to reproduce the `depth_8_state_proof` and `depth_8_storage_proof` examples, as is shown below.

### Library
#### Constants
The following constants mirror their Noir counterparts:
- `MAX_TRIE_NODE_LENGTH`
- `MAX_STORAGE_VALUE_LENGTH`
- `MAX_ACCOUNT_STATE_LENGTH`

#### Types
- `TrieProof` - A struct type with fields `key`, `proof`, `depth` and `value` as in the Noir library. Here, we use `Vec<u8>` in place of `[u8; _]` and `depth` is of type `usize`.

#### Methods
- `fn to_toml_string(self: &TrieProof, proof_name: &str) -> String` is a low-effort Toml string formatter for `TrieProof`.

#### Functions
- `async fn fetch_state_proof<T: JsonRpcClient>(provider: Provider<T>, block_number: U64, address: Address, max_depth: usize) -> Result<(Vec<u8>, TrieProof), Box<dyn std::error::Error>>` takes a JSON RPC provider, block number, address and maximum depth and returns a pair consisting of the state root and the state proof of the account with address `address` at the specified block number. The proof returned has fields whose dimensions match those of the fields of `StateProof<max_depth*MAX_TRIE_NODE_LENGTH>` in the Noir library.
- `async fn fetch_storage_proof<T: JsonRpcClient>(provider: Provider<T>, block_number: U64, key: H256, address: Address, max_depth: usize) -> Result<(Vec<u8>, TrieProof), Box<dyn std::error::Error>>` takes a JSON RPC provider, block number, key, address and maximum depth and returns a pair consisting of the storage root of the account with address `address` and the storage proof for the value resolved by key `key`, all with respect to the specified block number. The proof returned has fields whose dimensions match those of the fields of `Storage<max_depth*MAX_TRIE_NODE_LENGTH>` in the Noir library.
- `fn preprocess_proof(proof: Vec<Bytes>, key: Vec<u8>, value: Vec<u8>, max_depth: usize, max_node_len: usize, max_value_len: usize) -> Result<TrieProof, Box<dyn std::error::Error>>` preprocesses a trie proof returned by the JSON RPC to the flat padded format required by the Noir library, the parameters `max_depth`, and `max_value_len` corresponding to their uppercase Noir equivalents and `max_node_len` an upper bound on the byte length of a trie node, which is taken to be `MAX_NODE_LEN` for both state and storage proofs. This function is used by both of the preceding functions.


### Binary
#### Description
The program `ntp-fetch` is provided for testing purposes. It calls the `fetch_state_proof` or `fetch_storage_proof` function when called with the `state-proof`  or `storage-proof` subcommand.

The following are the global arguments:
- `-r, --rpc-url <RPC_URL>` is required and specifies the URL of the JSON-RPC supporting Ethereum node. This parameter may instead be provided as the environment variable `RPC_URL`.
- `-m, --max-depth <MAX_DEPTH>` is required and specifies the maximum allowable depth of the fetched proof.
- `-b, --block-number <BLOCK_NUMBER>` is optional and specifies the block number with respect to which the proof is fetched. If unspecified, it defaults to the current block number.
- `    --root-name <ROOT_NAME>` is optional and specifies the name of the retrieved trie root in the Toml output. If unspecified, it defaults to `state_root` or `storage_root`.
- `    --proof-name <PROOF_NAME>` is optional and specifies the name of the retrieved trie proof in the Toml output. If unspecified, it defaults to `state_proof` or `storage_proof`.

The following are the subcommands together with their arguments:
- `state-proof` fetches a state proof, processes it and prints it in Toml format.
  - `-a, --address <ADDRESS>` is required and specifies the address of the account whose state proof is retrieved.
- `storage-proof` fetches a storage proof, processes it and prints it in Toml format.
  - `-a --address <ADDRESS>` is required and specifies the address of the account from which a storage proof is retrieved.
  - `-k --key <KEY>` is required and specifies the key of the storage slot for which a storage proof is retrieved.
#### Examples
The binary may be invoked from the repository root by running `cargo run` with the appropriate arguments. For the following examples, we assume that the environment variable `RPC_URL` contains the address of JSON-RPC supporting Ethereum /archive/ node as provided e.g. by Infura. Failing this, any node may be used, but the block number argument will have to be changed (or omitted), in which case the examples will not reproduce the provided test cases.

- The `depth_8_state_proof` test data may be reproduced by calling
```
cargo run state-proof -m 8 --address 0xb47e3cd837dDF8e4c57f05d70ab865de6e193bbb -b 14194126 > tests/depth_8_state_proof/Prover.toml
```
- The `depth_8_storage_proof` test data may be reproduced by calling
```
cargo run storage-proof -m 8 --address 0xb47e3cd837dDF8e4c57f05d70ab865de6e193bbb --key 0xbbc70db1b6c7afd11e79c0fb0051300458f1a3acb8ee9789d9b6b26c61ad9bc7 -b 14194126 > tests/depth_8_storage_proof/Prover.toml
```

## Consuming this library

With Nargo v0.10.4, you can depend on this library by adding the following to your `Nargo.toml`:

```toml
[dependencies]
noir_trie_proofs = { git = "aragonzkresearch/noir-trie-proofs", tag = "main", directory = "lib" }
```

## Testing

To run the unit tests, you can run `nargo test` in the project root.

To run the integration tests, you can execute against various projects in `tests/`:

- `nargo execute --package depth_8_state_proof`
- `nargo execute --package depth_8_storage_proof`
- `nargo execute --package one_level`
- `nargo execute --package rlp_decode`

## Benchmarks

### depth_8_storage_proof

As of Noir v0.21.0 paired with the default proving backend, circuit size of the depth_8_storage_proof test program is:

```
+-----------------------+------------------------+--------------+----------------------+
| Package               | Language               | ACIR Opcodes | Backend Circuit Size |
+-----------------------+------------------------+--------------+----------------------+
| depth_8_storage_proof | PLONKCSat { width: 3 } | 51563        | 1687738              |
+-----------------------+------------------------+--------------+----------------------+
```

#### CLI

On M2 Macbook Air, using Nargo v0.21.0 paired with the default proving backend:

Compiling takes approximately 2 seconds:

```
% time nargo compile --package depth_8_storage_proof
nargo compile --package depth_8_storage_proof  1.84s user 0.07s system 99% cpu 1.925 total
```

Executing for witness takes approximately 1 second:

```
% time nargo execute --package depth_8_storage_proof
[depth_8_storage_proof] Circuit witness successfully solved
nargo execute --package depth_8_storage_proof  1.40s user 0.05s system 140% cpu 1.028 total
```

Executing + proving (as `nargo prove` always re-executes for witness) takes approximately 1.5 mins:

```
% time nargo prove --package depth_8_storage_proof
nargo prove --package depth_8_storage_proof  408.52s user 18.15s system 548% cpu 1:17.81 total
```

NOTE: Running `nargo prove` the first time / before `nargo compile` would automatically include program compilation. Subsequent runs without program modifications would make use of the cached artifacts and provide more representative benchmarking results.