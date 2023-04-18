// RLP encoding/decoding for strings and lists of strings with at most MAX_ELEMENTS elements.
// For simplicity, only strings of length <= 55 bytes are considered.

// RLP type enum
global IS_STRING: comptime Field = 0;
global IS_LIST: comptime Field = 1;

// Constants expressing maximum sizes
global MAX_LENGTH_BYTES: comptime Field = 2; // Maximum number of bytes needed to express the byte length of RLP-encoded list.
global MAX_ELEMENTS: comptime Field = 17; // Maximum number of elements allowed in RLP list

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

    // A sign that something's gone wrong
    fn invalid() -> Self
    {
	RLP_Header {offset: 0, length: 0, data_type: 2}
    }
}

// RLP list struct represented by the offsets and lengths of the elements together with
// the total number of elements.
struct RLP_List
{
    offset: [Field; MAX_ELEMENTS],
    length: [Field; MAX_ELEMENTS],
    // Number of slots
    num_elements: Field
}

impl RLP_List
{
    // RLP list struct initialiser
    fn initialise() -> Self
    {
	let offset = [0; MAX_ELEMENTS];
	let length = [0; MAX_ELEMENTS];
	let num_elements = 0;

	RLP_List {offset, length, num_elements}
    }
}

// Decode length of RLP-encoded list or string
fn decode_length<N>(input: [u8; N]) -> RLP_Header
{
    let length = input.len();
    let prefix = input[0];

    if prefix <= 0x7f
    {
	RLP_Header::new(0,1,IS_STRING)
    }
    else if prefix <= 0xb7
    {
	constrain (length as u64 > prefix as u64 - 0x80);
        let strlen = (prefix - 0x80) as Field;
        RLP_Header::new(1, strlen, IS_STRING)
    }
    else if prefix <= 0xbf
    {
	let strlenlen = (prefix - 0xb7) as Field;
	constrain (strlenlen as u64 < MAX_LENGTH_BYTES as u64 + 1);
	let strlen = data_len(input,strlenlen) as Field;
	
	RLP_Header::new(1 + strlenlen, strlen, IS_STRING)
    }
    else if prefix <= 0xf7
    {
	constrain length as u64 > prefix as u64 - 0xc0;
        let lislen = (prefix - 0xc0) as Field;
        RLP_Header::new(1, lislen, IS_LIST)
    }
    else if length as u8 > prefix - 0xf7
    {
	let lislenlen = (prefix - 0xf7) as Field;
	constrain (lislenlen as u64 < MAX_LENGTH_BYTES as u64 + 1);
	let lislen = data_len(input,lislenlen) as Field;
	
	RLP_Header::new(1 + lislenlen, lislen, IS_LIST)	    
    }
    else
    {
	RLP_Header::invalid() // Something went wrong
    }
}


// Takes an array of the form
// [rlp_header, x1, ..., x_{byte_length}, ...]
// and a parameter byte_length, assumed <= MAX_LENGTH_BYTES,
// and returns the length represented by the bytes [x1, ..., x_{byte_length}].
// Defined for use in `decode_length`.
fn data_len<N>(arr: [u8; N], byte_length: Field) -> Field
{
    let mut out = 0;
    
    for i in 1..(MAX_LENGTH_BYTES + 1)
    {
	if (i as u64 <= byte_length as u64) & (i as u64 < arr.len() as u64)
	{
	    out = 256*out + arr[i] as Field;
	}
    }
    out
}


// RLP decode
// Here implemented only for depth 1
fn decode1<N>(input: [u8; N]) -> RLP_List
{
    let mut list = RLP_List::initialise();

    // Read header
    let rlp_header = decode_length(input);
    constrain rlp_header.data_type == IS_LIST; // Only handle lists

    let mut total_length = rlp_header.offset + rlp_header.length;
    let mut offset = rlp_header.offset;

    let mut element_number = 0;
    let mut element_ptr = 0;
    let mut element_length = 0;

    for i in 0..input.len()
    {
	if (i as u64 < total_length as u64) & (i as u64 >= offset as u64)
	{
		if element_length == 0 // Need to inspect RLP header of element
		{
		    let element_prefix = input[i];
		    constrain element_prefix <= 0xb7; // Handle only lists of strings of length <= 55 bytes

		    // Inspect
		    if element_prefix <= 0x7f // If the header represents the byte itself
		    {
			for j in 0..list.offset.len() // Loop over indices to overcome lack of dynamic array indexing
			{
			    if j == element_number
				{
				    list.offset[j] = i;
				    list.length[j] = 1;
				}
			}
			
			element_length = 1;
			element_ptr = 1;
		    }
		    else // The header indicates an element of length <= 55 bytes
		    {
			element_length = element_prefix-0x80;
			
			for j in 0..list.offset.len() // Loop as above
			{
			    if j == element_number
				{
				    list.offset[j] = (i+1);
				    list.length[j] = element_length as Field;
				}
			    }
			constrain total_length as u64 > element_length as u64;
		    }

		}
		else
		{
		    element_ptr += 1;
		}

		if element_ptr == element_length // Check if we've exhausted all of the element under consideration
		{
		    // Proceed to next element
		    element_number += 1;
		    constrain element_number as u64 <= MAX_ELEMENTS as u64;
		    list.num_elements += 1;
		    
		    // Reset variables
		    element_length = 0;
		    element_ptr = 0;
		}
	    }
    }
    list
}

#[test]
fn rlp_decode_test()
{
    // Decode empty list
    let empty_list = decode1([0xc0]);
    
    constrain empty_list.num_elements == 0;
    
    let input = [ 0xc9, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x68, 0, 0 ];
    let output = decode1(input);
    
    constrain output.num_elements == 3;
    constrain output.offset[0] == 2;
    constrain output.length[0] == 3;
    constrain output.offset[1] == 6;
    constrain output.length[1] == 3;
    constrain output.offset[2] == 9;
    constrain output.length[2] == 1;

        let input1 = [249,2,17,160,10,210,58,71,229,91,254,185,245,139,35,127,191,50,125,165,19,165,59,86,127,77,226,197,94,143,9,69,104,149,113,39,160,164,115,165,166,228,180,44,203,222,52,48,157,214,190,69,130,116,84,133,170,215,193,212,152,106,149,100,253,145,220,246,94,160,69,11,1,238,164,195,225,91,51,198,134,50,21,34,253,120,157,26,173,81,148,24,94,179,165,5,99,85,90,78,104,180,160,82,128,145,254,48,73,106,165,234,223,46,5,168,79,141,218,64,98,200,87,199,28,213,222,164,182,145,219,253,186,121,39,160,167,139,46,219,193,195,174,240,47,40,188,121,97,50,227,220,35,99,122,36,94,78,156,78,197,54,232,163,249,213,16,58,160,111,180,73,26,200,238,6,49,66,159,230,23,226,13,10,230,7,51,103,45,139,187,57,125,86,1,146,77,200,196,223,158,160,55,41,196,37,89,112,4,6,183,246,239,121,175,146,171,71,19,99,239,56,75,116,235,20,239,208,243,25,211,222,248,120,160,203,87,65,73,168,197,46,86,209,173,204,46,232,157,204,145,75,151,105,166,72,142,173,255,186,120,43,121,104,228,130,134,160,150,115,130,186,247,99,108,21,244,243,60,208,96,34,93,32,175,77,181,18,59,49,192,153,255,123,231,108,251,75,134,92,160,78,107,27,31,43,92,213,101,63,87,83,248,163,19,104,103,84,248,119,180,32,209,82,52,250,148,101,219,76,194,160,125,160,83,37,183,243,189,9,79,122,28,120,150,139,190,225,222,184,206,225,117,233,244,162,244,212,38,220,37,129,215,25,93,53,160,229,6,255,207,78,120,107,238,212,128,106,189,84,39,136,172,149,67,89,238,163,122,88,90,149,80,59,121,249,7,238,1,160,81,214,156,64,149,165,65,36,216,223,167,73,213,180,230,230,32,106,193,147,176,40,93,119,210,13,1,159,16,112,114,103,160,211,15,4,49,74,86,24,146,109,246,80,207,194,97,226,153,241,94,43,233,192,2,152,171,150,86,26,250,234,179,74,156,160,175,157,156,73,109,26,48,12,182,175,211,173,181,241,131,247,105,98,255,101,7,227,21,63,78,41,155,58,231,222,15,141,160,219,213,163,116,191,119,232,215,182,77,130,102,90,48,66,197,228,202,43,169,232,246,11,23,100,50,211,205,202,115,60,49,128];

    let output1 = decode1(input1);

    constrain output1.num_elements == 17;
}

#[test]
fn rlp_length_check()
{
    // List test case
    let x = decode_length([ 0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0 ]);
    constrain x.offset == 1;
    constrain x.length == 7;
    constrain x.data_type == IS_LIST;

    // String test case
    let y = decode_length([ 0x82, 0x04, 0x00 ]);
    constrain y.offset == 1;
    constrain y.length == 2;
    constrain y.data_type == IS_STRING;

    // Longer string test case
    let z = decode_length([185,4,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,0]);
    constrain z.offset == 3;
    constrain z.length == 1024;
    constrain z.data_type == IS_STRING;
}

#[test]
fn data_len_test()
{
    constrain data_len([185,4,0], 2) == 1024;
}
