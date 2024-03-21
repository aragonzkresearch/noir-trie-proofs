/// Ethereum trie proof implementation
use dep::std::hash::keccak256;
mod utils;
mod test;
mod utils_test;
mod node_utils;
mod node_utils_test;
mod const;
mod rlp; // Module for required RLP encoding/decoding

use crate::utils::{byte_to_nibbles, byte_value, assert_subarray, memcpy};
use crate::node_utils::{key_as_nibbles, verify_node_hash, resolve2, resolve_nibble32};
use crate::const::{MAX_TRIE_NODE_LENGTH, MAX_STORAGE_VALUE_LENGTH, MAX_ACCOUNT_STATE_LENGTH, KEY_LENGTH, NIBBLE_LENGTH, LEAF};

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

/// Type alias for storage proofs. Assumes value is left-padded with zeros.
type StorageProof<PROOF_LEN> = TrieProof<32, PROOF_LEN, MAX_STORAGE_VALUE_LENGTH>;

/// Type alias for storage proofs. Assumes value is left-padded with zeros.
type StateProof<PROOF_LEN> = TrieProof<20, PROOF_LEN, MAX_ACCOUNT_STATE_LENGTH>;

impl<PROOF_LEN, MAX_VALUE_LEN> TrieProof<32, PROOF_LEN, MAX_VALUE_LEN>
{
    /// Ethereum storage proof verifier. Returns true if all constraints are satisfied.
    ///
    /// # Arguments
    /// * `self` - The proof to be verified.
    /// * `storage_root` - The root of the storage trie as a hash
    ///
    /// # Quirks
    /// * `PROOF_LEN`, the length of the byte array representing the proof path, *must* be a multiple of MAX_TRIE_NODE_LENGTH.
    pub fn verify_storage_root(
        self,
        storage_root: [u8; KEY_LENGTH]
    ) -> bool
    {
        assert((PROOF_LEN as u32) % (MAX_TRIE_NODE_LENGTH as u32) == 0); // Check that N is a multiple of MAX_TRIE_NODE_LENGTH

        let key = keccak256(self.key, 32); // The path is traced out by the hashed key

        let key_nibbles: [u8; NIBBLE_LENGTH] = key_as_nibbles(key);
        
        let mut key_ptr: u64 = 0;

        let path = self.proof; // Proof path

        let depth = self.depth; // Depth of proof path

        let mut extracted_hash = storage_root;

        for i in 0..(path.len() as u64 / MAX_TRIE_NODE_LENGTH - 1)
        {
            verify_internal_node(&mut extracted_hash, &mut key_ptr, key_nibbles, path, depth, i);
        }

        self.verify_storage_leaf_node(extracted_hash, key.len(), key_ptr, key_nibbles);
        
        true
    }

    /// Verifies that terminal storage node hashes to extracted hash. Extracts value and verifies it against the argument value.
    ///
    /// # Arguments
    /// * `hash` - Hash extracted from the preceding node
    /// * `value` - Value to be verified
    /// * `value_length` - Length of the value
    /// * `key` - Key to be verified
    /// * `key_ptr` - Pointer to current nibble in the key
    /// * `key_nibbles` - Array containing the nibbles of the key
    /// * `path` - RLP-encoded proof path
    /// * `depth` - Depth of proof path
    pub fn verify_storage_leaf_node(self, hash: [u8; KEY_LENGTH], key_len: Field, key_ptr: u64, key_nibbles: [u8; NIBBLE_LENGTH]) 
    {
        let (value, mut value_length) = byte_value(self.value); // Value to verify together with its byte length
        
        let mut leaf_node = [0; MAX_TRIE_NODE_LENGTH];
        // Treat final node as the preceding nodes...
        memcpy(&mut leaf_node, self.proof, (self.depth - 1) * MAX_TRIE_NODE_LENGTH);

        assert(verify_node_hash(leaf_node, hash), "Storage root: leaf node hash does not match the hash extracted from the preceding node");

        let rlp_list: rlp::RLP_List<2> = rlp::decode1_small_lis(leaf_node); // Terminal node must be a 2-node, and both slots contain less than 56 bytes.
        
        // ...except extract a value rather than a key.
        let (node_type, mut extracted_value, extracted_value_length, terminal_key_ptr): (u64, [u8; 33], u64, u64) = resolve2(leaf_node, rlp_list, key_nibbles, key_ptr);
        assert(node_type == LEAF);

        assert((extracted_value_length as u32) <= MAX_STORAGE_VALUE_LENGTH as u32 + 1); // Extracted value be at most 33 bytes with RLP header
        assert(terminal_key_ptr == 2 * key_len as u64); // All of the key has been exhausted.

        // Decode extracted value
        let (dec_value_offset, dec_value_len) = rlp::decode0(extracted_value);
        assert(dec_value_len == value_length);
        assert_subarray(value, extracted_value, value_length, dec_value_offset);
    }
}

impl<PROOF_LEN, MAX_VALUE_LEN> TrieProof<20, PROOF_LEN, MAX_VALUE_LEN>
{
    /// Ethereum state proof verifier. Returns true if all constraints are satisfied.
    ///
    /// # Arguments
    /// * `self` - The proof to be verified.
    /// * `state_root` - The root of the state trie as a hash
    pub fn verify_state_root( // PROOF_LEN *must* be a multiple of MAX_TRIE_NODE_LENGTH!
        self,
        state_root: [u8; KEY_LENGTH] // Hash of root, i.e. first, node.
    ) -> bool
    {
        assert((PROOF_LEN as u32) % (MAX_TRIE_NODE_LENGTH as u32) == 0); // Check that N is a multiple of MAX_TRIE_NODE_LENGTH

        let key = keccak256(self.key, 20); // The path is traced out by the hashed key
        
        let key_nibbles: [u8; NIBBLE_LENGTH] = key_as_nibbles(key);
        
        let mut key_ptr: u64 = 0;

        let path = self.proof; // Proof path

        let depth = self.depth; // Depth of proof path

        let mut extracted_hash = state_root;

        for i in 0..(path.len() as u64 / MAX_TRIE_NODE_LENGTH - 1)
        {
            verify_internal_node(&mut extracted_hash, &mut key_ptr, key_nibbles, path, depth, i);
        }

        self.verify_state_leaf_node(extracted_hash, key.len(), key_ptr, key_nibbles);
        
        true
    }

    /// Verifies that terminal state node hashes to extracted hash. Extracts value and verifies it against the argument value.
    ///
    /// # Arguments
    /// * `extracted_hash` - Hash extracted from the preceding node
    /// * `value` - Value to be verified
    /// * `value_length` - Length of the value
    /// * `key` - Key to be verified
    /// * `key_ptr` - Pointer to current nibble in the key
    /// * `key_nibbles` - Array containing the nibbles of the key
    /// * `path` - RLP-encoded proof path
    /// * `depth` - Depth of proof path
    fn verify_state_leaf_node(self, extracted_hash: [u8; KEY_LENGTH], key_len: Field, key_ptr: u64, key_nibbles: [u8; NIBBLE_LENGTH]) 
    {
        let (value, mut value_length) = byte_value(self.value); // Value to verify together with its byte length
        
        let mut leaf_node = [0; MAX_TRIE_NODE_LENGTH];
        // Treat final node as the preceding nodes...
        memcpy(&mut leaf_node, self.proof, (self.depth - 1) * MAX_TRIE_NODE_LENGTH);

        assert(verify_node_hash(leaf_node, extracted_hash), "State root: leaf node hash does not match the hash extracted from the preceding node");

        let rlp_list: rlp::RLP_List<2> = rlp::decode1(leaf_node); // Terminal node must be a 2-node
        
        // ...except extract a value rather than a key.
        let (node_type, mut extracted_value, extracted_value_length, terminal_key_ptr): (u64, [u8; MAX_ACCOUNT_STATE_LENGTH], u64, u64) = resolve2(leaf_node, rlp_list, key_nibbles, key_ptr);
        assert(node_type == LEAF);

        assert((extracted_value_length as u32) <= (MAX_VALUE_LEN as u32)); // Extracted value should fit in a byte array of length MAX_ACCOUNT_STATE_LENGTH.
        assert(terminal_key_ptr == 2 * key_len as u64); // All of the key has been exhausted.

        // No need to decode data, but it ought to be a list.
        assert(extracted_value[0] >= 0xc0);
        assert(extracted_value_length == value_length);
        assert_subarray(value, extracted_value, value_length, 0);
    }
}

/// Verifies that an internal node hashes to extracted hash. Extracts the next hash and advances the key pointer.
///
/// # Arguments
/// * `extracted_hash` - Hash extracted from the preceding node
/// * `key_ptr` - Pointer to current nibble in the key
/// * `key_nibbles` - Array containing the nibbles of the key
/// * `path` - RLP-encoded proof path
/// * `depth` - Depth of proof path
/// * `cur_depth` - Current depth in the proof path
fn verify_internal_node<PROOF_LEN>(extracted_hash: &mut [u8; KEY_LENGTH], key_ptr: &mut u64, key_nibbles: [u8; NIBBLE_LENGTH], path: [u8; PROOF_LEN], depth: u64, cur_depth: u64)
{
    let in_range = (cur_depth as u8) < (depth - 1) as u8; // Range indicator

    let cur_depth_or_0 = if (in_range) {cur_depth} else {0}; // Restrict index to range {0, ..., depth - 2}
    let mut node = [0; MAX_TRIE_NODE_LENGTH];
    // Populate node array
    memcpy(&mut node, path, cur_depth_or_0 * MAX_TRIE_NODE_LENGTH);

    assert(!in_range | verify_node_hash(node, *extracted_hash), "Internal node hash does not match the hash extracted from the preceding node");
    
    // Extract hash and advance key pointer if within range
    let (node_type, resolved_key, key_pointer): (u64, [u8; KEY_LENGTH], u64) = resolve_nibble32(key_nibbles, if in_range { *key_ptr } else { 0 }, node); // Resolve next nibble(s)
    assert(!in_range | (node_type != LEAF));
    *extracted_hash = if in_range {resolved_key} else {*extracted_hash};
    *key_ptr = if in_range {key_pointer} else {*key_ptr};
}



