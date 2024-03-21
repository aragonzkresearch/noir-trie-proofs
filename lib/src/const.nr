/// Node type
global BRANCH: u64 = 2; global EXTENSION: u64 = 0; global LEAF: u64 = 1;

/// Constants for 32-byte long keys; TODO: Omit these when it is possible to replace constants with numeric generics.
global KEY_LENGTH: u64 = 32; // (fixed) key length in bytes
global NIBBLE_LENGTH: u64 = 64; // = 2*KEY_LENGTH

/// Maximum trie node length. For tries with 32-byte long keys, we we can bound the byte length of any node from above by this constant.
global MAX_TRIE_NODE_LENGTH: u64 = 532; // = MAX_RLP_LIST_HEADER_LENGTH (= 1 + MAX_LENGTH_BYTES)
//   + 16*MAX_RLP_ELEMENT_LENGTH (= 16*(1 + KEY_LENGTH))
// + LENGTH_OF_NULL_ELEMENT (= 1)

/// Maximum size of the value in a storage slot
global MAX_STORAGE_VALUE_LENGTH: u64 = 32;

/// Maximum number of bytes in an account state
global MAX_ACCOUNT_STATE_LENGTH: u64 = 134;

/// Maximum number of RLP-encoded elements in a trie node
global MAX_NUM_FIELDS: u64 = 17;