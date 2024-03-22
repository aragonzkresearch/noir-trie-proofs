/// Node type
global BRANCH: u64 = 2; global EXTENSION: u64 = 0; global LEAF: u64 = 1;

/// Length of keccak256 hash.
global HASH_LENGTH: u64 = 32;
global HASH_NIBBLE_LENGTH: u64 = 64; // = 2 * HASH_LENGTH


global RLP_IDX_KEY_LENGTH: u64 = 3;
global RLP_IDX_KEY_NIBBLE_LENGTH: u64 = 6; // TODO: make sure it really is 6

/// Maximum trie node length. For tries with 32-byte long keys, we can bound the byte length of any node from above by this constant.
global MAX_TRIE_NODE_LENGTH: u64 = 532; // = MAX_RLP_LIST_HEADER_LENGTH (= 1 + MAX_LENGTH_BYTES)
//   + 16 * MAX_RLP_ELEMENT_LENGTH (= 16 * (1 + HASH_LENGTH))
// + LENGTH_OF_NULL_ELEMENT (= 1)

/// Maximum size of the value in a storage slot
global MAX_STORAGE_VALUE_LENGTH: u64 = 32;

/// Maximum number of bytes in an account state
global MAX_ACCOUNT_STATE_LENGTH: u64 = 134;

// TODO: make it generic
global MAX_RECEIPT_RLP_LENGTH: u64 = 525; // TODO: Understand why

/// Maximum number of RLP-encoded elements in a trie node
global MAX_NUM_FIELDS: u64 = 17;