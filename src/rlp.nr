// RLP decoding library

// Constants expressing maximum data sizes
// TODO: Incorporate as comptime Field function parameter whenever this is possible
global MAX_LEN_IN_BYTES: Field = 2; // Max number of bytes required to represent length of a string or list

// Trie nodes have <= 17 fields/slots
global MAX_FIELDS: Field = 17;

// RLP data type enum
global IS_STRING: Field = 0;
global IS_LIST: Field = 1;

// RLP header struct obtained from length decoding
struct RLP_Header
{
    offset: Field, // Offset of first (RLP-encoded) element
    length: Field, // Length of RLP-encoded object starting from the above offset
    data_type: Field // IS_STRING or IS_LIST
}

// Useful methods
impl RLP_Header
{
    // RLP header constructor
    fn new(offset: Field, length: Field, data_type: Field) -> Self
    {
	    RLP_Header {offset, length, data_type}
    }
}

// RLP list struct represented by the offsets and lengths of the fields together with
// the total number of fields.
struct RLP_List<NUM_FIELDS>
{
    offset: [Field; NUM_FIELDS],
    length: [Field; NUM_FIELDS],
    data_type: [Field; NUM_FIELDS],
    // Number of fields
    num_fields: Field
}

impl<NUM_FIELDS> RLP_List<NUM_FIELDS>
{
    // RLP list constructor
    fn new(offset: [Field; NUM_FIELDS], length: [Field; NUM_FIELDS], data_type: [Field; NUM_FIELDS], num_fields: Field) -> Self
    {
	    RLP_List {offset, length, data_type, num_fields}
    }
}

// Extract length from bytes following prefix in case data is of length >= 56 bytes
fn data_len<N>(arr: [u8; N], lenlen: Field) -> Field
{
    let mut out = 0;

    for i in 0..MAX_LEN_IN_BYTES
    {
	    let arr_len_pred = (((i + 1) as u8) < (arr.len() as u8)) as Field;
	    let len_len_pred = (((i as u8) < (lenlen as u8)) as Field);
	    out = len_len_pred*(256*out + (arr[arr_len_pred*(i + 1)] as Field)) + (1-len_len_pred)*out;
    }

    out
}

// Determine offset, length and type of RLP-encoded data
// May be used on any RLP-encoded byte array
fn decode_len<N>(arr: [u8; N]) -> RLP_Header
{
    let prefix = arr[0];

    // Prefix range predicates
    let prefix_p1 = (prefix < 0x80); // Single byte
    let prefix_p2 = (prefix < 0xb8); // 0-55 byte string
    let prefix_p3 = (prefix < 0xc0); // >55-byte string
    let prefix_p4 = (prefix < 0xf8); // 0-55 byte list
    // Else >55-byte list
    
    let offset = strict_if(prefix_p1,
			               0,
			               strict_if(prefix_p2,
				                     1,
				                     strict_if(prefix_p3,
					                           (1 + prefix - 0xb7) as Field,
					                           strict_if(prefix_p4,
							                             1,
							                             (1 + prefix - 0xf7) as Field))));

    let len = strict_if(prefix_p1,
			            1,
			            strict_if(prefix_p2,
				                  (prefix - 0x80) as Field,
				                  strict_if(prefix_p3,
					                        data_len(arr, (prefix - 0xb7) as Field),
					                        strict_if(prefix_p4,
						                              (prefix - 0xc0) as Field,
						                              data_len(arr, (prefix - 0xf7) as Field)))));
    
    
    let data_type = (prefix >= 0xc0) as Field;

    RLP_Header::new(offset, len, data_type)
}

// RLP string decoder
fn decode0<N>(input: [u8; N])
			              -> (Field, Field)
{
    let mut RLP_Header {offset, length, data_type} = decode_len(input); // Read RLP header of input
    
    let total_len = length + offset; // Data length including RLP header

    assert(data_type == IS_STRING); // decode0 expects an RLP-encoded string
    
    assert((total_len as u64) <= (input.len() as u64)); // Payload should be fully contained in input array

    (offset, length)
}

// RLP list decoder
// Decodes one level at a time by returning the number of (outer) fields,
// the offsets of the fields, their lengths and their types (IS_STRING or IS_LIST).
fn decode1<N, NUM_FIELDS>(input: [u8; N])
			              -> RLP_List<NUM_FIELDS>
{
    let mut num_fields: Field = 0; // Number of fields
    let mut dec_off = [0; NUM_FIELDS]; // Decoded offsets
    let mut dec_len = [0; NUM_FIELDS]; // Decoded lengths
    let mut dec_type = [0; NUM_FIELDS]; // Decoded types

    let mut RLP_Header {offset, length: payload_len, data_type: input_type} = decode_len(input); // Read RLP header of input
    
    let total_len = payload_len + offset; // Data length including RLP header

    assert(input_type == IS_LIST); // Should be dealing with a list
    
    assert((total_len as u64) <= (input.len() as u64)); // Payload should be fully contained in input array

    // Process each element of the list
    for i in 0..NUM_FIELDS
    {
        let loop_p = (offset != total_len) as Field; // Loop predicate: Take action only if there is data left to parse.

        // Make sure the index doesn't overshoot
        let header: [u8; MAX_LEN_IN_BYTES + 1] = take_dot_drop(input, offset); // Read element header
	    let RLP_Header {offset: field_off, length: field_len, data_type: field_type} = decode_len(header); // Decode length of element
        let total_field_len = field_off + field_len; // Length of element + header

        // Assign decoded data and set them to 0 if loop predicate false (Convenient for testing; could remove this later)
        dec_off[i] = loop_p*(offset + (1-field_type)*field_off); // If the ith slot contains a list, include its RLP header.
	    dec_len[i] = loop_p*(field_len + field_type*field_off); // If the ith slot contains a list, make sure to include the length of its header in the decoded data.
        dec_type[i] = loop_p*(field_type);

        // Calculate new offset
        offset += loop_p*total_field_len;
        num_fields += loop_p;
    }

    // Ensure that we have exhausted the data
    assert(total_len == offset);

    RLP_List::new(dec_off, dec_len, dec_type, num_fields)
}

// Special purpose RLP list decoder for lists of strings of length < 56 bytes
fn decode1_small_lis<N, NUM_FIELDS>(input: [u8; N])
			              -> RLP_List<NUM_FIELDS>
{
    let mut num_fields: Field = 0; // Number of fields
    let mut dec_off = [0; NUM_FIELDS]; // Decoded offsets
    let mut dec_len = [0; NUM_FIELDS]; // Decoded lengths
    let mut dec_type = [0; NUM_FIELDS]; // Decoded types

    let mut RLP_Header {offset, length: payload_len, data_type: input_type} = decode_len(input);
    let total_len = payload_len + offset;

    assert(input_type == IS_LIST); // Should be dealing with a list
    assert((total_len as u64) <= (input.len() as u64)); // Payload should be fully contained in input array

    // Fill up the NUM_FIELDS fields
    for i in 0..NUM_FIELDS
    {
        let loop_p = (offset != total_len) as Field; // Loop predicate: Take action only if there is data left to parse.
        
        let header = input[offset]; // Read field header

        assert(header < 0xb8); // Header must represent a string of length < 56 bytes.

        let field_type = IS_STRING; // Always dealing with strings here

        let single_byte_p = (header < 0x80) as Field; // 1 if `header` represents a single byte.

        let field_off = 1 - single_byte_p; // If `header` < 0x80, then we are dealing with a single byte whose value
        // is given by header. Else, the string begins at the following index.

        let field_len = single_byte_p*1 + (1-single_byte_p)*((header - 0x80) as Field); // Single byte means len = 1,
        // else subtract 0x80 from the header to determine len.

        let total_field_len = field_off + field_len; // Length of field + header

        // Assign decoded data and set them to 0 if loop predicate false (Convenient for testing; could remove this later)
        dec_off[i] = loop_p*(offset + field_off);
	    dec_len[i] = loop_p*(field_len);
        dec_type[i] = loop_p*(field_type);

        // Calculate new offset
        offset += loop_p*total_field_len;
        num_fields += loop_p;
    }

    // Ensure that we have exhausted the data
    assert(total_len == offset);

    RLP_List::new(dec_off, dec_len, dec_type, num_fields)
}

#[test]
fn rlp_decode_test()
{
    // Decode empty list
    let empty_list: RLP_List<MAX_FIELDS> = decode1([0xc0]);
    
    assert(empty_list.num_fields == 0);
    
    // let input = [ 0xc9, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x68, 0, 0 ];
    // let output: RLP_List<MAX_FIELDS> = decode1(input);
    
    // assert(output.num_fields == 3);
    // // Offsets
    // assert(output.offset == [2,6,9,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);
    // // // Lengths
    // assert(output.length == [3,3,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);

    // let input1 = [249,2,17,160,10,210,58,71,229,91,254,185,245,139,35,127,191,50,125,165,19,165,59,86,127,77,226,197,94,143,9,69,104,149,113,39,160,164,115,165,166,228,180,44,203,222,52,48,157,214,190,69,130,116,84,133,170,215,193,212,152,106,149,100,253,145,220,246,94,160,69,11,1,238,164,195,225,91,51,198,134,50,21,34,253,120,157,26,173,81,148,24,94,179,165,5,99,85,90,78,104,180,160,82,128,145,254,48,73,106,165,234,223,46,5,168,79,141,218,64,98,200,87,199,28,213,222,164,182,145,219,253,186,121,39,160,167,139,46,219,193,195,174,240,47,40,188,121,97,50,227,220,35,99,122,36,94,78,156,78,197,54,232,163,249,213,16,58,160,111,180,73,26,200,238,6,49,66,159,230,23,226,13,10,230,7,51,103,45,139,187,57,125,86,1,146,77,200,196,223,158,160,55,41,196,37,89,112,4,6,183,246,239,121,175,146,171,71,19,99,239,56,75,116,235,20,239,208,243,25,211,222,248,120,160,203,87,65,73,168,197,46,86,209,173,204,46,232,157,204,145,75,151,105,166,72,142,173,255,186,120,43,121,104,228,130,134,160,150,115,130,186,247,99,108,21,244,243,60,208,96,34,93,32,175,77,181,18,59,49,192,153,255,123,231,108,251,75,134,92,160,78,107,27,31,43,92,213,101,63,87,83,248,163,19,104,103,84,248,119,180,32,209,82,52,250,148,101,219,76,194,160,125,160,83,37,183,243,189,9,79,122,28,120,150,139,190,225,222,184,206,225,117,233,244,162,244,212,38,220,37,129,215,25,93,53,160,229,6,255,207,78,120,107,238,212,128,106,189,84,39,136,172,149,67,89,238,163,122,88,90,149,80,59,121,249,7,238,1,160,81,214,156,64,149,165,65,36,216,223,167,73,213,180,230,230,32,106,193,147,176,40,93,119,210,13,1,159,16,112,114,103,160,211,15,4,49,74,86,24,146,109,246,80,207,194,97,226,153,241,94,43,233,192,2,152,171,150,86,26,250,234,179,74,156,160,175,157,156,73,109,26,48,12,182,175,211,173,181,241,131,247,105,98,255,101,7,227,21,63,78,41,155,58,231,222,15,141,160,219,213,163,116,191,119,232,215,182,77,130,102,90,48,66,197,228,202,43,169,232,246,11,23,100,50,211,205,202,115,60,49,128];

    // let output1: RLP_List<MAX_FIELDS> = decode1(input1);

    // assert(output1.num_fields == 17);
    // assert(output1.offset == [4, 37, 70, 103, 136, 169, 202, 235, 268, 301, 334, 367, 400, 433, 466, 499, 532]);
    // assert(output1.length == [32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 0]);
    // assert(output1.data_type == [0; MAX_FIELDS]);
}


#[test]
fn data_len_test()
{
    assert(data_len([185,4,0], 2) == 1024);
}

#[test]
fn rlp_length_check()
{
    // List test case
    let in0: [u8; MAX_LEN_IN_BYTES + 1] = take_dot_drop([ 0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0 ], 0);
    let x = decode_len(in0);
    assert(x.offset == 1);
    assert(x.length == 7);
    assert(x.data_type == IS_LIST);

    // String test case
    let y = decode_len([ 0x82, 0x04, 0x00 ]);
    assert(y.offset == 1);
    assert(y.length == 2);
    assert(y.data_type == IS_STRING);

    // // Longer string test case
    let z = decode_len([185,4,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,0]);
    assert(z.offset == 3);
    assert(z.length == 1024);
    assert(z.data_type == IS_STRING);
}

fn take_dot_drop<T, N, M>(arr: [T; N], n: Field) -> [T; M] // = drop n . take M
{
    let mut out = [dep::std::unsafe::zeroed(); M];

    for i in 0..M
    {
	    let j = (((i + n) as u64) < N) as Field * (i + n); // Restrict to proper range and fill with arr[0] otherwise.
	    out[i] = arr[j];
    }

    out
}

fn strict_if(pred: bool, x: Field, y: Field) -> Field
{
    let pred_f = pred as Field;
    pred_f*x + (1-pred_f)*y
}
