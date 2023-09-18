# noir-trie-proofs

## Description

This library contains primitives necessary for

- RLP decoding in the form of look-up table construction
- Ethereum state and storage proof verification (or verification of any trie proof involving 32-byte long keys)

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
- `MAX_TRIE_NODE_LENGTH` is the maximum number of bytes in a trie node under the assumption of 32-byte long keys.
- `MAX_ACCOUNT_STATE_LENGTH` is the maximum number of bytes in an account state, i.e. the maximum number of bytes in the value slot of the terminal node of a state proof.
- `MAX_NUM_FIELDS` is the maximum number of RLP-encoded elements in a trie node, i.e. 17.
- `EXTENSION` and `LEAF` form an enum representing the extension and leaf types for 2-nodes.

#### Types
- `TrieProof<KEY_LEN, PROOF_LEN, VALUE_LEN>` represents a trie proof whose key is`KEY_LEN` bytes long and whose value and proof lengths are at most `VALUE_LEN` and `PROOF_LEN` bytes long respectively. It has fields for the key (`key: [u8; KEY_LEN]`), value (`value: [u8; VALUE_LEN]`), proof path (`proof: [u8; PROOF_LEN]`) and depth (`depth: Field`). For technical reasons, the methods described below assume that `PROOF_LEN` is a multiple of `MAX_TRIE_NODE_LENGTH` and that nodes in the trie proof are right-padded with zeros and subsequently concatenated in order to form the proof path array. If trie proofs are expressed as a list of lists of 8-bit words, the preprocessing required may be expressed by the following mapping:

```haskell
pad :: [[Word8]] -> [Word8]
pad xs = concat
         $ map (\x -> x ++ byte_padding x)
         $ xs ++ depth_padding
  where
    byte_padding node = replicate (max_trie_node_length - length node) 0
    depth_padding = replicate (max_depth - length xs) []
```

  For storage proofs, the relevant type is `TrieProof<32, PROOF_LEN, VALUE_LEN>` and for state proofs it is `TrieProof<20, PROOF_LEN, VALUE_LEN>`. Note that for the latter, even though we think of the keys as being 20 bytes long, the trie itself takes the `keccak256`-hashed key as input, i.e. a 32-byte key is resolved, which is taken care of under the hood in the following methods.

#### Methods
- `fn verify_storage_root(self: TrieProof<32, PROOF_LEN, VALUE_LEN>, storage_root: [u8; KEY_LENGTH]) -> bool`  takes a storage proof (`self`) and storage root (`storage_root`) as inputs and returns `true` if the proof is successfully verified. `PROOF_LEN` is subject to the restrictions explained above and `VALUE_LEN <= 32` should be large enough to encapsulate the value that the key resolves to in the proof, which is encoded as a big-endian byte array.
- `fn verify_state_root(self: TrieProof<20, PROOF_LEN, VALUE_LEN>, state_root: [u8; KEY_LENGTH]) -> bool` takes a state proof (`self`) and state root (`state_root`) as inputs and returns `true` if the proof is successfully verified. `PROOF_LEN` is as before, and `VALUE_LEN <= MAX_ACCOUNT_STATE_LENGTH` should be large enough to encapsulate the value the key resolves to in the proof, which is the RLP-encoded account state associated with the address given by `self.key`.

#### Examples
Besides the unit tests, the following examples are provided as integration tests:
- `tests/depth_8_state_proof` verifies a private state proof of depth 8 with public input given by the state root.
- `tests/depth_8_storage_proof` verifies a private state proof of depth less than 8 with public input given by the storage root.
- `tests/one_level` illustrates one step through a storage proof by taking a node, a key and a pointer to the current offset (in nibbles) to extract the hash of the following node as well as a pointer to the next nibble to be resolved.
- `tests/rlp_decode` illustrates RLP decoding.

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
