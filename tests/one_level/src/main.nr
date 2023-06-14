use dep::trie;

fn main(node: [u8; trie::MAX_NODE_LENGTH], key: [u8; trie::KEY_LENGTH], key_offset: Field) {
    let _lookup = trie::get_fixed32(trie::key_as_nibbles(key), key_offset, node);
}
