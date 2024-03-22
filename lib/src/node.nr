use crate::const::{KEY_LENGTH, NIBBLE_LENGTH, MAX_NUM_FIELDS, BRANCH, LEAF, MAX_TRIE_NODE_LENGTH};
use crate::utils::{byte_to_nibbles, memcpy};
use crate::rlp;
use dep::std::hash::keccak256;

/// Verifies that an internal node hashes to extracted hash. Extracts the next hash and advances the key pointer.
///
/// # Arguments
/// * `extracted_hash` - Hash extracted from the preceding node
/// * `key_ptr` - Pointer to current nibble in the key
/// * `key_nibbles` - Array containing the nibbles of the key
/// * `path` - RLP-encoded proof path
/// * `depth` - Depth of proof path
/// * `cur_depth` - Current depth in the proof path
pub(crate) fn verify_internal_node<PROOF_LEN>(extracted_hash: &mut [u8; KEY_LENGTH], key_ptr: &mut u64, key_nibbles: [u8; NIBBLE_LENGTH], path: [u8; PROOF_LEN], depth: u64, cur_depth: u64)
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

/// Trie node hash verifier. Returns true if the node has the specified keccak256 hash.
///
/// # Arguments
/// * `node` - RLP-encoded trie node
/// * `hash` - 32-byte hash value
pub(crate) fn verify_node_hash<N>(node: [u8; N], hash: [u8; KEY_LENGTH])
                           -> bool
{
    // Extract actual length of node
    let node_length = { let rlp_header = rlp::decode_len(node); rlp_header.offset + rlp_header.length }; // Determine length of node

    // Extra safety
    let in_range = ((node_length as u32) > (node.len() as u32)) as u64;
    let safe_length = in_range * node.len() as u64 + (1 - in_range) * node_length;
    
    // Compute Keccak256 hash of node
    let node_hash = keccak256(node, safe_length as u32);

    // Compare hashes
    node_hash == hash
}

/// Key-to-nibble converter. Returns an array (twice the length of the input array)
/// of 4-bit elements representing the nibbles of the input array.
///
/// # Arguments
/// * `key` - Array of bytes representing a key
pub fn key_as_nibbles<KEY_LEN, NIB_LEN>(key: [u8; KEY_LEN]) -> [u8; NIB_LEN]
{
    assert(NIB_LEN == 2*KEY_LEN);
    
    let mut nibkey = [0; NIB_LEN];
    
    for i in 0..KEY_LEN
    {
        let nibs = byte_to_nibbles(key[i]);

        nibkey[2*i] = nibs.0;
        nibkey[2*i + 1] = nibs.1;
    }
    
    nibkey
}

/// Leaf/extension node nibble decoder. Returns the nibbles in the first field
/// in a right-padded array together with the number of nibbles.
///
/// # Arguments
/// * `input`: The first field of a leaf/extension node as a (right-padded) byte array
/// * `length`: The actual length of the data in `input`
pub(crate) fn compact_decode<MAX_ENC_LEN, NIB_LEN>(input: [u8; MAX_ENC_LEN], length: u64) -> ([u8; NIB_LEN], u64)
{

    assert((2 as u32)*(MAX_ENC_LEN as u32) <= ((NIB_LEN + 2) as u32)); // MAX_ENC_LEN should be NIB_LEN/2 or NIB_LEN/2 + 1. TODO
    
    let mut nibble = [0 as u8; NIB_LEN];
    let mut out_length = 0;

    let mut prev_nibbles = byte_to_nibbles(input[0]);
    let mut cur_nibbles = (0,0);
    
    let first_nibble = prev_nibbles.0;
    let parity = first_nibble as u1;

    // Consistency checks
    // The first nibble should always be less than 4.
    assert(first_nibble < 4);
    // Parity consistency: If we are dealing with an even number of nibbles, then the second nibble should be 0.
    assert(((1-parity) as u8)*prev_nibbles.1 == 0);

    for i in 0..(MAX_ENC_LEN - 1)
    {
        let x = input[i + 1];
        cur_nibbles = byte_to_nibbles(x); // x decomposed into two nibbles

        nibble[2*i] = (parity as u8)*prev_nibbles.1 + (1 - (parity as u8))*cur_nibbles.0;
        nibble[2*i + 1] = (parity as u8)*cur_nibbles.0 + (1 - (parity as u8))*cur_nibbles.1;

        prev_nibbles = cur_nibbles;
    }

    out_length = 2*length + (parity as u64) - 2;


    assert((out_length as u32) <= (NIB_LEN as u32)); // Sanity check
    let out = (nibble, out_length);
    out
}

/// Non-terminal nibble resolver (assuming 32-byte fixed key length).
/// Returns the node type, extracted hash and an advanced key pointer.
///
/// # Arguments
/// * `key` - Array containing the nibbles to be resolved
/// * `key_ptr` - Pointer to the nibbles in `key` to be resolved
/// * `node` - RLP-encoded byte array of branch or extension node
pub fn resolve_nibble32<N>(
    key: [u8; NIBBLE_LENGTH],
    mut key_ptr: u64,
    node: [u8; N]) ->
    (u64,
     [u8; KEY_LENGTH], // Extracted hash
     u64) // New key pointer
{
    let rlp_list: rlp::RLP_List<MAX_NUM_FIELDS> = rlp::decode1_small_lis(node); // Assumes no intermediate nodes have slots with >= 56 bytes, which is the case for state and storage proofs.
    let num_fields = rlp_list.num_fields;

    let mut node_type = BRANCH;
    let mut resolved_key = [0; KEY_LENGTH];
    let mut resolved_key_length = 0;
    
    if num_fields == 2 // If we are dealing with an extension node
    {
        // Resolve 2-node        
        let node_resolution: (u64, [u8; KEY_LENGTH], u64, u64) = resolve2(node, rlp_list, key, key_ptr);
        
        // Deconstruct
        node_type = node_resolution.0;
        key_ptr = node_resolution.3;
        resolved_key = node_resolution.1;
        resolved_key_length = node_resolution.2;        
    }
    else
    {
        // Since we are dealing with a fixed key length, the last slot must be empty.
        assert(rlp_list.length[16] == 0);

        // Resolve 17-node
        let node_resolution = resolve17(node, rlp_list, key, key_ptr);

        key_ptr = node_resolution.2;
        resolved_key = node_resolution.0;
        resolved_key_length = node_resolution.1;
    }

    assert((node_type == LEAF) | (resolved_key_length == KEY_LENGTH));
    
    (node_type, resolved_key, key_ptr)
}

/// Branch (i.e. 17-node) resolver. Assumes 32-byte fixed key length (i.e. slot 17 should be empty).
/// Returns the extracted hash, its length and the advanced key pointer.
///
/// # Arguments
/// * `node` - RLP-encoded branch node
/// * `rlp_list` - RLP list look-up table for `node`
/// * `key` - Array containing the nibbles to be resolved
/// * `key_ptr` - Pointer to the nibbles in `key` to be resolved
// TODO: Generalise to accommodate for variable key lengths.
pub(crate) fn resolve17<N, NUM_FIELDS>(
    node: [u8; N],
    rlp_list: rlp::RLP_List<NUM_FIELDS>,
    key: [u8; NIBBLE_LENGTH],
    mut key_ptr: u64)
    -> (
    [u8; KEY_LENGTH], // Extracted hash
    u64, // Extracted key length
    u64) // New key pointer
{
    // We should be dealing with a node containing 17 elements
    assert(rlp_list.num_fields == 17);
    
    // The first 16 slots should be of length 32 or 0.
    for i in 0..16
    {
        assert(rlp_list.length[i] as Field * (rlp_list.length[i] as Field - KEY_LENGTH as Field) == 0);
    }

    // And the last slot should be empty
    assert(rlp_list.length[16] == 0);
    
    let cur_nibble = key[key_ptr];
    let resolved_key_length = rlp_list.length[cur_nibble as u64];

    assert(resolved_key_length == KEY_LENGTH);
    assert((key_ptr as u32) < (NIBBLE_LENGTH as u32)); // Fixed-length key => Node cannot be terminal.
    
    key_ptr += 1;

    let nibble_offset = rlp_list.offset[cur_nibble as u64];

    let mut resolved_key = [0; KEY_LENGTH];
    
    for j in 0..KEY_LENGTH
    {
        resolved_key[j] = node[nibble_offset + j];
    }


    let out = (resolved_key, resolved_key_length, key_ptr);

    out
}

// Resolve a 2-node, i.e. a LEAF or EXTENSION.
/// Leaf/extension (i.e. 2-node) resolver.
/// Returns the node type (LEAF or EXTENSION), extracted value, its length and the advanced key pointer.
///
/// # Arguments
/// * `node` - RLP-encoded leaf/extension node
/// * `rlp_list` - RLP list look-up table for `node`
/// * `key` - Array containing the nibbles to be resolved
/// * `key_ptr` - Pointer to the nibbles in `key` to be resolved
pub(crate) fn resolve2<N, NUM_FIELDS, MAX_VALUE_LEN>(
    node: [u8; N],
    rlp_list: rlp::RLP_List<NUM_FIELDS>,
    key: [u8; NIBBLE_LENGTH],
    mut key_ptr: u64)
    -> (
    u64,
    [u8; MAX_VALUE_LEN], // Extracted value
    u64, // Value length
    u64) // New key offset
{
    // We should be dealing with a node containing two elements
    assert(rlp_list.num_fields == 2);
    
    let mut value = [0; MAX_VALUE_LEN];
    
    let first_slot: [u8; 1 + NIBBLE_LENGTH/2] = rlp::take_dot_drop(node,rlp_list.offset[0]); // TODO: Replace consts with numeric generics when it is possible to use them in array length expressions
    
    let (nib, niblen): ([u8; NIBBLE_LENGTH], u64) = compact_decode(first_slot, rlp_list.length[0]);

    // Length checks.
    // Should not go past 64 nibbles.
    assert(((NIBBLE_LENGTH - key_ptr) as u32) >= niblen as u32);

    // Check that the `niblen` nibbles in the first slot match up with the `niblen` nibbles
    // in `key` starting from offset `key_ptr`.
    for i in 0..NIBBLE_LENGTH
    {
        if (i as u32) < (niblen as u32)
        {
            assert(nib[i] == key[key_ptr + i]);
        }
    }

    // Store length of value obtained
    let value_length = rlp_list.length[1];
    // This should not exceed MAX_VALUE_LEN
    assert((value_length as u32) <= (MAX_VALUE_LEN as u32));
    
    // Increment offset
    key_ptr += niblen;

    // Store value
    assert(((rlp_list.offset[1] + MAX_VALUE_LEN) as u32) <= (N as u32)); // MAX_VALUE_LEN should be consistent with maximum node length
    for i in 0..MAX_VALUE_LEN
    {
        value[i] = node[rlp_list.offset[1] + i];
    }

    // Ensure we've followed the right kind of node, i.e. if we're not at the end of the key,
    // we should have followed an extension node, and if we are, then we should have followed a leaf node.
    let node_type_nibble = first_slot[0] >> 4;

    ((node_type_nibble > 1) as u64, value, value_length, key_ptr)
}