use dep::trie;
global DEPTH8_MAX: Field = 4256;

fn main(root_hash: pub [u8; 32], trie_proof: trie::TrieProof32<DEPTH8_MAX>) {
    assert(trie::verify_proof32(root_hash, trie_proof));
}
