use crate::{
    trie_proof::TrieProof,
    const::{KEY_LENGTH, NIBBLE_LENGTH, MAX_TRIE_NODE_LENGTH, MAX_ACCOUNT_STATE_LENGTH, LEAF},
    utils::{memcpy, byte_value, assert_subarray},
    node::{key_as_nibbles, verify_internal_node, verify_node_hash, resolve2}
};
use dep::std::hash::keccak256;
use crate::rlp;

/// Type alias for storage proofs. Assumes value is left-padded with zeros.
type StateProof<PROOF_LEN> = TrieProof<20, PROOF_LEN, MAX_ACCOUNT_STATE_LENGTH>;

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
    fn verify_state_leaf_node(self, extracted_hash: [u8; KEY_LENGTH], key_len: u64, key_ptr: u64, key_nibbles: [u8; NIBBLE_LENGTH]) 
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
