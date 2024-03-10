use dep::trie;

fn main(node: [u8; trie::MAX_TRIE_NODE_LENGTH], key: [u8; trie::KEY_LENGTH], key_offset: u64) {
    let _lookup: (u64, [u8; trie::KEY_LENGTH], u64) = trie::resolve_nibble32(trie::key_as_nibbles(key), key_offset, node);
}
