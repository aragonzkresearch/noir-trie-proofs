// Ethereum trie proof implementation
use dep::std::hash::keccak256;

mod rlp; // Module for required RLP encoding/decoding

global KEY_LENGTH: comptime Field = 32; // key length in bytes; <= 55 for simplicity

global MAX_COMPACT_ENCODE_LENGTH: Field = 33; // = KEY_LENGTH + 1

global NIBBLE_LENGTH: comptime Field = 64; // = 2*KEY_LENGTH

global MAX_NODE_LENGTH: comptime Field = 532; // = MAX_RLP_LIST_HEADER_LENGTH (= 1 + MAX_LENGTH_BYTES)
//   + 16*MAX_RLP_ELEMENT_LENGTH (= 16*(1 + KEY_LENGTH))
// + LENGTH_OF_NULL_ELEMENT (= 1)

global MAX_NUM_FIELDS: Field = 17;

// Ethereum trie proof verifier for 32 byte long keys
fn verify_proof_fixed<N>( // N *must* be a multiple of MAX_NODE_LENGTH!
    root_hash: [u8; KEY_LENGTH], // Hash of root, i.e. first, node.
    path: [u8; N], // RLP encoded proof path; assumed to be obtained by right-padding each node (e.g. with zeros) to form a list of length MAX_NODE_LENGTH and concatenated in order.
    depth: Field, // Depth of path. Necessary for technical reasons.
    key: [u8; KEY_LENGTH], // Key to look up along path
    value: [u8; KEY_LENGTH], // Value to verify
    mut value_length: Field) -> bool // Length of value to verify
{
    assert((N as u32) % (MAX_NODE_LENGTH as u32) == 0); // Check that N is a multiple of MAX_NODE_LENGTH
    
    let key_nibbles = key_as_nibbles(key);
    
    let mut key_offset = 0;

    let mut cur_value = root_hash;

    let mut cur_value_length = 32;
    
    let mut cur_node = [0; MAX_NODE_LENGTH];

    // TODO: Loop till depth - 1, then handle the final level separately. Also constrain value length == 32!
    for i in 0..path.len()/MAX_NODE_LENGTH
    {
	    if i as u8 < depth as u8
	    {
	        for j in 0..MAX_NODE_LENGTH
	        {
		        cur_node[j] = path[j + i*MAX_NODE_LENGTH];
	        }

	        // First compute current node hash
	        let node_length = { let rlp_header = rlp::decode_len(cur_node); rlp_header.offset + rlp_header.length } as u32; // Determine length of node
	        let cur_hash = keccak256(cur_node, node_length); // Compute keccak256 hash
	        assert(cur_hash == cur_value); // Make sure hashes are consistent
            assert(cur_value_length == 32); // Value length should be 32, since all values extracted are hashes except possibly for the final one.
 	        let lookup = get_fixed(key_nibbles, key_offset, cur_node); // Follow node
 	        cur_value = lookup.0;
	        cur_value_length = lookup.1;
 	        key_offset = lookup.2;

	    }
    }
    

    assert(key_offset == 2*key.len()); // All of the key has been exhausted.

    // Need to encode value

    let (enc_value, enc_value_length) = encode_value(value, value_length);

    assert(cur_value_length == enc_value_length); // Value length equality

    for i in 0..KEY_LENGTH
    {
	    if i as u8 < value_length as u8
	    {
	        assert(cur_value[i] == enc_value[i]); // Value equality
	    }
    }
    
    true
}

// Encode value according to 'node cap function', which ensures values are <= 32 bytes long
// in a trie (see Appendix D of Ethereum Yellow Paper).
fn encode_value<N>(value: [u8; N], value_length: Field) -> ([u8; KEY_LENGTH], Field)
{
    assert(value.len() as u32 >= value_length as u32);

    let mut out_value = [0; KEY_LENGTH];
    
    if value_length == 0 // Check for empty string
    {
    	let out = (out_value, value_length);
	    out
    }
    else if (value_length == 1) & value[0] < 0x7f // Check if string is a small enough lone byte
    {
        out_value[0] = value[0];
        let out = (out_value, value_length);

        out
    }
    else if value_length as u32 < 31 // Check for sufficiently short string
    {
	    out_value[0] = 0x80 + value_length as u8;
	    
 	    for i in 1..value.len()
 	    {
 	        out_value[i] = value[i-1];
 	    }
	    
	    let out = (out_value, value_length + 1);

	    out
    }
    else // String too long, so hash it.
    {
	    // Run Keccak256 on [value[0], ... , value[value_length - 1]]
	    let out = (out_value, 32);
	    out
    }
}

// Key-to-nibble conversion
fn key_as_nibbles<KEY_LEN, NIB_LEN>(key: [u8; KEY_LEN]) -> [u4; NIB_LEN]
{
    assert(NIB_LEN == 2*KEY_LEN);
    
    let mut nibkey = [0; NIB_LEN];
    
    for i in 0..KEY_LEN
    {
	    nibkey[2*i + 1] = (key[i] & 0x0f) as u4;
	    nibkey[2*i] = ((key[i] - nibkey[2*i + 1] as u8) >> 4) as u4;
    }
    
    nibkey
}

// Decode leaf/extension node's first slot into nibbles
// Assume this slot is a 33-byte right-padded array
// Returns nibbles in a right-padded array together with the number of nibbles.
fn compact_decode(input: [u8; MAX_COMPACT_ENCODE_LENGTH], length: Field) -> ([u4; NIBBLE_LENGTH], Field)
{
    let mut nibble = [0 as u4; NIBBLE_LENGTH];
    let mut out_length = 0;

	let mut prev_nibbles = ((input[0] >> 4) as u4, (input[0] & 0x0f) as u4);
    let mut cur_nibbles = (0,0);
    
    let first_nibble = prev_nibbles.0;
	let parity = first_nibble as u1;

    // Consistency checks
    // The first nibble should always be less than 4.
    assert(first_nibble < 4);
    // Parity consistency: If we are dealing with an even number of nibbles, then the second nibble should be 0.
    assert(((1-parity) as u4)*prev_nibbles.1 == 0);

    for i in 0..KEY_LENGTH
    {
        let x = input[i + 1];
        cur_nibbles = ((x >> 4) as u4, (x & 0x0f) as u4);

        nibble[2*i] = (parity as u4)*prev_nibbles.1 + (1 - (parity as u4))*cur_nibbles.0;
        nibble[2*i + 1] = (parity as u4)*cur_nibbles.0 + (1 - (parity as u4))*cur_nibbles.1;

        prev_nibbles = cur_nibbles;
    }

	out_length = 2*length + (parity as Field) - 2;


    assert((out_length as u32) <= (NIBBLE_LENGTH as u32)); // Sanity check
    let out = (nibble, out_length);
    out
}

// Check whether RLP-decoded list represents a valid trie node
fn valid_node_shape_p<M,N>(
    fixed_key_length_p: comptime bool, // Predicate indicating whether key length is fixed or variable
    rlp_list: rlp::RLP_List<N>
) -> bool
{
    let num_fields = rlp_list.num_fields;
    let slot_len = rlp_list.length;
    
    // First check the number of fields
    if num_fields == 2
    {
        // The first slot's length should be <= 1 (compact encoding header) + 32
        assert((slot_len[0] as u32) <= ((KEY_LENGTH + 1) as u32));
        
        // The second slot's length should be <= 32
        assert((slot_len[1] as u32) <= (KEY_LENGTH as u32));

        true
    }
    else if num_fields == 17
    {
        // The first 16 slots should be of length 32 or 0.
        for i in 0..16
        {
            assert(slot_len[i]*(slot_len[i] - KEY_LENGTH) == 0);
        }

        // If we are dealing with a fixed key length, the last slot should be of length 0.
        // Else it should be of length <= 32
        assert((fixed_key_length_p & (slot_len[16] == 0))
               | (!fixed_key_length_p & ((slot_len[16] as u32) <= (KEY_LENGTH as u32))));

        true
    }
    else
    {
        false
    }
}

// Look up nibble (or sequence of nibbles) in RLP-encoded node
fn get_fixed<N>(
    key: [u4; NIBBLE_LENGTH],
    mut key_ptr: Field,
    node: [u8; N]) ->
    ([u8; KEY_LENGTH], // Value obtained from node
    Field, // Length of value obtained from node (between 0 and KEY_LENGTH)
    Field) // New key offset
{
    let rlp_list: rlp::RLP_List<MAX_NUM_FIELDS> = rlp::decode1(node);
    let num_fields = rlp_list.num_fields;

    // Make sure node has the right shape, i.e. that it has the right number
    // of slots and that its slots have the right lengths.
    assert(valid_node_shape_p(true, rlp_list));
    
    let mut value = [0; KEY_LENGTH];
    let mut value_length = 0;

    if num_fields == 2 // If we are dealing with a leaf/extension node
    {
        let first_slot: [u8; KEY_LENGTH + 1] = rlp::take_with_offset(node,rlp_list.offset[0]);
	    let (nib, niblen) = compact_decode(first_slot, rlp_list.length[0]);

        // Length check. Should not go past 64 nibbles.
	    assert(NIBBLE_LENGTH as u32 - key_ptr as u32 >= niblen as u32);

        // Check that the `niblen` nibbles in the first slot match up with the `niblen` nibbles
        // in `key` starting from offset `key_ptr`.

        // TODO: Fix this problematic code!
        // for i in 0..NIBBLE_LENGTH
        // {
        //     if (i as u32) < (niblen as u32)
        //     {
        //         assert(nib[key_ptr + i] == key[i]);
        //     }
        // }

        // Slightly more complicated working code
        let mut nib_ptr = 0;
        for i in 0..NIBBLE_LENGTH
        {
            if ((i as u32) >= (key_ptr as u32)) & ((i as u32) <= ((key_ptr + niblen) as u32))
            {
                assert(nib[nib_ptr] == key[i]);
                nib_ptr += 1;
            }
        }

        // Store length of value obtained
	    value_length = rlp_list.length[1];

        // Increment offset
        key_ptr += niblen;

	    // Store value
		for i in 0..KEY_LENGTH
		{
		    value[i] = node[rlp_list.offset[1] + i];
		}

        // Ensure we've followed the right kind of node, i.e. if we're not at the end of the key,
        // we should have followed an extension node, and if we are, then we should have followed a leaf node.
        let node_type = first_slot[0] >> 4;
        assert(((key_ptr == NIBBLE_LENGTH) & (node_type > 1))
               | (key_ptr != NIBBLE_LENGTH) & (node_type < 2));
        
    }
    else
    {
	    let cur_nibble = key[key_ptr * (((key_ptr as u32) < (NIBBLE_LENGTH as u32)) as Field)]; // TODO: Avoid this.
	    value_length = rlp_list.length[cur_nibble as Field];

	    key_ptr += 1;

	    let nibble_offset = rlp_list.offset[cur_nibble as Field];
		for j in 0..KEY_LENGTH
		{
		    value[j] = node[nibble_offset + j];
		}
	}
    
    let out = (value, value_length, key_ptr);

    out
}

// Trie proof test
#[test]
fn cryptopunk1() // Who owns the first cryptopunk? cf. https://www.youtube.com/watch?v=2-yYtEJdrFY&t=266s
{
    // Block 14194126
    // Address: 0xb47e3cd837dDF8e4c57f05d70ab865de6e193bbb
    // Value: 0xb88f61e6fbda83fbfffabe364112137480398018
    // Key: 0xbbc70db1b6c7afd11e79c0fb0051300458f1a3acb8ee9789d9b6b26c61ad9bc7
    // Fetch proof using e.g.
    // curl https://eth-mainnet.g.alchemy.com/v2/your-api-key \
    // -X POST \
    // -H "Content-Type: application/json" \
    // -d '{"jsonrpc":"2.0","method":"eth_getProof","params":["0xb47e3cd837dDF8e4c57f05d70ab865de6e193bbb",["0xbbc70db1b6c7afd11e79c0fb0051300458f1a3acb8ee9789d9b6b26c61ad9bc7"],"latest"],"id":1}'

    let path = [249,2,17,160,131,222,227,85,174,97,156,127,191,169,123,140,230,159,249,132,240,154,181,243,84,51,151,47,88,26,53,171,190,213,205,185,160,229,63,170,108,2,183,41,202,254,50,239,181,218,135,195,8,21,100,37,42,62,117,201,80,140,169,199,152,187,0,30,191,160,169,218,185,94,14,107,53,100,115,116,135,137,188,18,95,207,182,185,56,177,139,5,118,44,30,206,202,84,53,126,44,109,160,188,117,50,13,5,219,241,132,23,179,73,107,238,66,145,170,27,62,178,71,145,173,76,216,31,42,126,67,46,40,234,65,160,56,185,158,70,248,209,40,213,179,137,41,131,155,77,64,164,242,169,24,242,168,49,36,168,79,130,172,138,98,13,141,14,160,194,18,203,128,147,53,23,137,77,219,80,157,139,57,233,39,114,219,144,69,52,96,79,131,146,232,68,222,89,91,235,162,160,191,212,103,121,255,198,244,86,229,4,9,218,180,94,131,235,106,220,183,95,3,82,104,60,111,20,115,172,183,18,202,35,160,200,204,47,138,125,135,230,115,9,24,170,45,75,88,181,173,229,247,16,111,237,182,167,60,205,19,217,68,86,241,161,214,160,194,1,45,132,217,242,127,219,118,58,85,225,67,139,98,169,99,60,242,186,130,120,131,160,215,14,62,65,101,165,53,167,160,175,200,34,123,178,141,77,67,228,252,69,109,200,60,27,28,0,178,219,252,91,47,100,195,190,128,45,196,5,96,98,183,160,198,132,64,192,40,105,95,204,180,173,60,217,197,191,249,205,67,33,193,246,11,167,81,184,138,106,156,33,143,239,250,56,160,67,164,81,196,212,211,46,230,53,153,22,28,81,97,239,230,159,240,109,143,248,243,21,116,109,48,142,250,75,118,104,115,160,189,194,208,247,5,235,15,199,194,91,157,121,242,245,193,1,169,118,195,215,51,197,2,222,79,15,67,98,185,239,123,173,160,40,250,181,145,247,42,198,42,104,245,191,66,0,67,152,247,12,220,163,19,95,216,163,14,97,48,13,67,44,92,252,125,160,251,1,134,193,15,46,176,143,28,66,178,148,103,88,37,164,69,155,75,67,194,70,248,28,196,201,10,68,122,0,135,105,160,160,29,82,173,191,137,225,140,77,68,120,88,139,209,23,23,251,22,129,148,136,139,141,212,100,44,198,38,46,217,60,158,128,249,2,17,160,240,221,35,192,34,64,110,48,186,9,130,70,201,43,141,190,210,216,91,87,72,214,144,194,248,64,64,165,141,112,22,179,160,166,50,206,215,247,106,66,47,103,45,150,112,167,63,103,59,63,177,111,129,155,67,152,164,19,6,141,199,2,164,247,202,160,100,236,241,61,41,155,249,81,182,64,34,225,46,220,31,63,90,151,91,255,29,193,58,49,109,235,56,21,246,58,16,99,160,70,150,205,16,82,199,200,205,61,182,26,145,171,110,131,203,246,170,7,243,203,79,216,227,112,159,0,186,82,36,72,59,160,123,39,110,202,80,98,63,47,27,111,158,103,65,133,212,175,165,156,96,80,186,88,234,82,148,145,190,103,90,130,38,21,160,33,20,100,92,250,63,113,203,209,194,23,188,13,237,219,69,43,123,120,12,79,133,79,161,120,185,84,118,7,251,132,16,160,249,84,201,100,25,202,200,41,6,211,118,40,122,59,106,97,181,175,18,199,192,21,153,123,212,84,84,181,80,143,48,237,160,210,245,166,106,201,156,229,19,101,113,15,82,70,90,58,114,165,193,3,146,212,139,143,245,189,55,191,86,83,135,31,106,160,11,162,234,207,240,91,155,86,19,68,244,50,131,236,140,222,18,129,243,19,63,111,96,12,140,157,72,213,77,233,0,126,160,8,57,227,179,220,228,76,216,159,224,234,44,126,155,24,85,102,253,127,197,169,120,41,176,230,13,231,91,171,162,229,69,160,12,174,232,237,84,114,140,212,41,142,149,3,132,221,232,117,149,199,207,74,77,198,162,154,185,241,35,52,228,251,254,39,160,179,165,104,1,2,235,205,172,12,255,11,73,43,48,30,90,25,208,181,35,209,207,210,112,212,70,231,216,251,157,168,221,160,97,73,209,221,129,7,203,113,14,5,240,163,152,4,141,187,121,234,1,165,174,246,157,0,48,42,192,105,166,64,61,21,160,237,33,177,147,8,139,156,202,104,19,51,96,17,245,99,50,242,238,254,222,234,136,244,227,138,69,3,45,198,91,101,1,160,70,98,16,229,221,172,207,159,98,51,174,150,20,51,59,233,143,159,6,68,112,9,122,196,64,229,56,171,194,38,223,133,160,174,150,11,38,214,72,120,225,198,168,11,121,24,79,3,167,203,49,251,26,133,68,180,186,94,101,230,211,81,110,163,73,128,249,2,17,160,47,69,48,53,130,59,211,11,161,1,213,54,30,201,238,178,220,114,179,211,153,17,50,56,66,84,35,30,9,246,222,174,160,90,113,236,5,199,178,159,238,6,57,151,8,151,218,159,45,241,125,148,18,198,139,154,225,57,171,38,129,40,24,226,126,160,23,1,151,85,165,9,212,114,100,197,87,35,107,179,126,231,8,114,135,16,213,253,139,43,82,190,250,58,126,11,23,249,160,42,168,203,133,243,35,55,5,250,244,4,21,83,100,84,236,203,181,178,252,137,85,84,6,184,152,197,83,243,248,232,155,160,160,203,36,105,6,142,43,229,53,15,71,197,119,247,79,212,130,50,151,143,10,12,58,66,31,221,110,128,250,109,67,154,160,253,218,130,199,68,153,141,19,216,149,99,99,54,201,171,223,216,171,18,55,15,120,74,175,68,139,14,189,190,63,239,59,160,94,199,190,215,147,134,100,152,161,160,185,168,247,212,4,251,50,232,217,119,113,181,209,74,197,20,73,107,31,77,59,174,160,11,214,206,214,112,141,172,209,164,254,114,134,128,150,153,24,116,222,47,164,24,127,5,79,209,197,29,129,244,71,204,116,160,123,189,205,165,68,166,56,90,164,171,94,191,145,184,43,155,210,126,23,227,163,21,0,116,2,236,1,161,2,44,58,79,160,116,95,232,43,89,83,196,203,4,225,246,152,56,41,102,200,245,170,93,63,47,200,9,14,155,202,82,53,171,161,114,240,160,76,121,242,107,106,6,5,54,174,132,114,165,21,175,174,15,43,239,28,25,91,101,150,231,68,5,149,23,170,155,165,208,160,209,166,45,131,155,154,139,188,146,138,128,171,125,95,170,4,255,248,54,97,157,173,85,243,0,182,186,151,29,211,49,46,160,215,233,123,209,95,254,3,211,130,155,102,147,195,1,36,117,91,101,21,132,128,227,100,46,25,219,109,94,68,99,173,45,160,81,121,242,103,174,208,230,76,220,90,237,138,17,38,100,96,7,172,79,100,236,33,60,19,179,223,227,216,154,212,4,149,160,18,90,118,20,167,150,50,13,211,230,184,27,165,84,167,110,4,205,149,83,174,208,43,122,14,58,249,30,101,194,41,76,160,74,237,218,87,155,244,168,177,208,213,70,251,69,136,69,249,52,41,122,105,254,194,143,31,47,31,235,100,46,76,57,47,128,248,177,128,128,128,128,128,160,28,249,182,132,51,145,111,142,211,178,180,147,92,161,244,19,73,10,187,240,227,19,159,57,142,9,254,81,139,248,67,175,128,128,160,73,97,138,225,4,245,30,87,189,138,110,63,153,2,254,23,33,35,77,206,160,31,55,142,20,57,31,122,160,140,79,188,128,160,15,143,44,113,58,7,157,9,191,167,58,140,221,27,221,62,79,240,181,31,177,121,148,175,107,82,237,215,126,250,137,75,128,160,41,222,166,27,179,177,3,173,193,241,7,231,155,19,232,201,100,152,160,60,219,21,187,170,229,4,97,78,229,104,217,14,160,0,188,57,48,132,60,195,69,115,33,11,219,146,191,236,195,45,181,187,210,167,19,203,73,127,26,141,27,147,110,109,204,128,128,128,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,246,159,32,176,50,213,165,250,58,91,101,68,86,110,228,106,15,107,143,232,177,55,94,200,120,220,59,230,88,11,7,132,149,149,148,184,143,97,230,251,218,131,251,255,250,190,54,65,18,19,116,128,57,128,24,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let depth = 5; // Actual depth

    let storage_hash = [0x91,0x1b,0xb4,0x34,0xb8,0x45,0x6f,0x99,0x79,0xf4,0x2a,0x4e,0x3b,0x0c,0x4d,0x00,0x25,0xee,0x93,0xc3,0xb1,0x2a,0xb7,0x97,0x41,0xf7,0x08,0x17,0x02,0x2d,0x08,0x0e];
    let key = [0xed,0x65,0xb0,0x32,0xd5,0xa5,0xfa,0x3a,0x5b,0x65,0x44,0x56,0x6e,0xe4,0x6a,0x0f,0x6b,0x8f,0xe8,0xb1,0x37,0x5e,0xc8,0x78,0xdc,0x3b,0xe6,0x58,0x0b,0x07,0x84,0x95]; // keccak256([0xbb,0xc7,0x0d,0xb1,0xb6,0xc7,0xaf,0xd1,0x1e,0x79,0xc0,0xfb,0x00,0x51,0x30,0x04,0x58,0xf1,0xa3,0xac,0xb8,0xee,0x97,0x89,0xd9,0xb6,0xb2,0x6c,0x61,0xad,0x9b,0xc7]
    let value = [0xb8,0x8f,0x61,0xe6,0xfb,0xda,0x83,0xfb,0xff,0xfa,0xbe,0x36,0x41,0x12,0x13,0x74,0x80,0x39,0x80,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    let value_length = 20;
    assert(verify_proof_fixed
           (storage_hash, path, depth, key, value, value_length));

}

// Auxiliary function tests
#[test]
fn fixed_key_lookup_test()
{
    let x3 = [246,159,32,176,50,213,165,250,58,91,101,68,86,110,228,106,15,107,143,232,177,55,94,200,120,220,59,230,88,11,7,132,149,149,148,184,143,97,230,251,218,131,251,255,250,190,54,65,18,19,116,128,57,128,24,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
    let rlp_list3: rlp::RLP_List<MAX_NUM_FIELDS> = rlp::decode1(x3);
    assert(rlp_list3.num_fields == 2);
    assert(rlp_list3.length[0] == 31);
    assert(rlp_list3.length[1] == 21);
    let (value3, value_length3, _key_offset3) = get_fixed(
	    key_as_nibbles([0xed,0x65,0xb0,0x32,0xd5,0xa5,0xfa,0x3a,0x5b,0x65,0x44,0x56,0x6e,0xe4,0x6a,0x0f,0x6b,0x8f,0xe8,0xb1,0x37,0x5e,0xc8,0x78,0xdc,0x3b,0xe6,0x58,0x0b,0x07,0x84,0x95]),
	    4,
	    x3);
    assert(value_length3 == 21);
    assert(value3[0] == 0x94);
    assert(value3[20] == 0x18);
    
}

#[test]
fn nibble_check()
{
    assert(key_as_nibbles([0x56,0xe8,0x1f,0x17,0x1b,0xcc,0x55,0xa6,0xff,0x83,0x45,0xe6,0x92,0xc0,0xf8,0x6e,0x5b,0x48,0xe0,0x1b,0x99,0x6c,0xad,0xc0,0x01,0x62,0x2f,0xb5,0xe3,0x63,0xb4,0x21]) == [0x05,0x06,0x0e,0x08,0x01,0x0f,0x01,0x07,0x01,0x0b,0x0c,0x0c,0x05,0x05,0x0a,0x06,0x0f,0x0f,0x08,0x03,0x04,0x05,0x0e,0x06,0x09,0x02,0x0c,0x00,0x0f,0x08,0x06,0x0e,0x05,0x0b,0x04,0x08,0x0e,0x00,0x01,0x0b,0x09,0x09,0x06,0x0c,0x0a,0x0d,0x0c,0x00,0x00,0x01,0x06,0x02,0x02,0x0f,0x0b,0x05,0x0e,0x03,0x06,0x03,0x0b,0x04,0x02,0x01]);
}

#[test]
fn compact_decode_test()
{
    let (nibble0, len0) = compact_decode([0x11, 0x23, 0x45,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 3); // TODO: Legit header!
    assert(len0 == 5);
    assert([nibble0[0], nibble0[1], nibble0[2], nibble0[3], nibble0[4]] == [1,2,3,4,5]);

    let (nibble1, len1) = compact_decode([0x20, 0x0f, 0x1c, 0xb8, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 4); // TODO
    assert(len1 == 6);
    assert([nibble1[0], nibble1[1], nibble1[2], nibble1[3], nibble1[4], nibble1[5]] == [0,15,1,12,11,8]);

    let (nibble2, len2) = compact_decode([0x3f, 0x1c, 0xb8, 0x99, 0xab, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0], 3);
    assert(len2 == 5);
    assert([nibble2[0], nibble2[1], nibble2[2], nibble2[3], nibble2[4]] == [15,1,12,11,8]);
    
}

// Omit the following test due to compiler panic

#[test]
fn encode_value_test()
{
    let val1 = [0xb8,0x8f,0x61,0xe6,0xfb,0xda,0x83,0xfb,0xff,0xfa,0xbe,0x36,0x41,0x12,0x13,0x74,0x80,0x39,0x80,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00];
    let val1_length = 20;

    let encoded_val1 = encode_value(val1,val1_length);

    assert(encoded_val1.0 == [0x94,0xb8,0x8f,0x61,0xe6,0xfb,0xda,0x83,0xfb,0xff,0xfa,0xbe,0x36,0x41,0x12,0x13,0x74,0x80,0x39,0x80,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]);
    assert(encoded_val1.1 == 21);
}
