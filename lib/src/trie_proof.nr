/// Type for storage proofs corresponding to `ethers-rs` StorageProof type
/// Involves 32-byte keys
// TODO: Add comptime u64 parameters to
// - bound the sizes of the nodes embedded in `proof` to allow arbitrary fixed-length keys
// - bound the key length to allow variable-length keys
// These would require the ability to declare arrays of length expressed as a comptime u64 variable.
struct TrieProof<KEY_LEN, PROOF_LEN, MAX_VALUE_LEN>
{
    /// Unhashed key to look up along proof path
    key: [u8; KEY_LEN],
    /// RLP encoded proof path; assumed to be obtained by appropriately right-padding each node (e.g. with zeros) and concatenating in order. The size of each node will depend on the application, e.g. MAX_TRIE_NODE_LENGTH for storage proofs.
    proof: [u8; PROOF_LEN],
    /// Depth of proof. Necessary for technical reasons.
    depth: u64,
    /// The value the given proof path should terminate with.
    value: [u8; MAX_VALUE_LEN]
}
