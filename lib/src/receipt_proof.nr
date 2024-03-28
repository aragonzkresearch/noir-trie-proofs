use crate::{
    trie_proof::TrieProof,
    const::{MAX_TRIE_NODE_LENGTH, LEAF, HASH_LENGTH, HASH_NIBBLE_LENGTH, RLP_IDX_KEY_NIBBLE_LENGTH},
    utils::{memcpy, byte_value, assert_subarray},
    node::{key_as_nibbles, verify_internal_node, verify_node_hash, resolve2}
};
use crate::rlp;

/// Type alias for receipt proofs. Assumes value is left-padded with zeros.
type ReceiptProof<PROOF_LEN, RECEIPT_RLP_LENGTH> = TrieProof<3, PROOF_LEN, RECEIPT_RLP_LENGTH>;

impl<PROOF_LEN, RECEIPT_RLP_LENGTH> TrieProof<3, PROOF_LEN, RECEIPT_RLP_LENGTH>
{
    /// Ethereum receipt proof verifier. Returns true if all constraints are satisfied.
    ///
    /// # Arguments
    /// * `self` - The proof to be verified.
    /// * `receipt_root` - The root of the receipt trie as a hash
    pub fn verify_receipt_root(
        self,
        receipt_root: [u8; HASH_LENGTH] // Hash of root, i.e. first, node.
    ) -> bool
    {
        assert((PROOF_LEN as u32) % (MAX_TRIE_NODE_LENGTH as u32) == 0, "PROOF_LEN must be a multiple of MAX_TRIE_NODE_LENGTH");

        let (key, key_len) = byte_value(self.key);
        
        let key_nibbles: [u8; RLP_IDX_KEY_NIBBLE_LENGTH] = key_as_nibbles(key);
        
        let mut key_ptr: u64 = 0;

        let path = self.proof; // Proof path

        let depth = self.depth; // Depth of proof path

        let mut extracted_hash = receipt_root;

        for i in 0..(path.len() as u64 / MAX_TRIE_NODE_LENGTH - 1)
        {
            verify_internal_node(&mut extracted_hash, &mut key_ptr, key_nibbles, path, depth, i);
        }

        self.verify_receipt_leaf_node(extracted_hash, key_len, key_ptr, key_nibbles);
        
        true
    }

    /// Verifies that terminal receipt node hashes to extracted hash. Extracts value and verifies it against the argument value.
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
    fn verify_receipt_leaf_node(self, extracted_hash: [u8; HASH_LENGTH], key_len: u64, key_ptr: u64, key_nibbles: [u8; RLP_IDX_KEY_NIBBLE_LENGTH]) 
    {
        let (value, value_length) = byte_value(self.value);
        
        let mut leaf_node = [0; MAX_TRIE_NODE_LENGTH];
        // Treat final node as the preceding nodes...
        memcpy(&mut leaf_node, self.proof, (self.depth - 1) * MAX_TRIE_NODE_LENGTH);

        assert(verify_node_hash(leaf_node, extracted_hash), "Receipt root: leaf node hash does not match the hash extracted from the preceding node");

        let rlp_list: rlp::RLP_List<2> = rlp::decode1(leaf_node); // Terminal node must be a 2-node
        
        // ...except extract a value rather than a key.
        let (node_type, mut extracted_value, extracted_value_length, terminal_key_ptr): (u64, [u8; RECEIPT_RLP_LENGTH], u64, u64) = resolve2(leaf_node, rlp_list, key_nibbles, key_ptr);
        assert(node_type == LEAF, "Receipt root: terminal node is not a leaf node");

        assert((extracted_value_length as u32) <= (RECEIPT_RLP_LENGTH as u32), "Receipt root: extracted value must fit in a byte array of length RECEIPT_RLP_LENGTH");
        assert(terminal_key_ptr == 2*key_len as u64, "Receipt root: not all of the key has been exhausted");

        assert(extracted_value_length == value_length, "Receipt root: extracted value length does not match value_length");
        assert_subarray(value, extracted_value, RECEIPT_RLP_LENGTH, 0);
    }
}
