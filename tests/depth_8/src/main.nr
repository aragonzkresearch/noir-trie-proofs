use dep::trie;
global DEPTH8_MAX: Field = 4256;

fn main(root_hash: [u8; 32], path: [u8; DEPTH8_MAX], depth: Field, key: [u8; 32], value: [u8; 32], value_length: Field) {
    assert(trie::verify_proof(root_hash, path, depth, key, value, value_length));
}
