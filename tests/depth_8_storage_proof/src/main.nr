use dep::trie;
global DEPTH8_MAX: Field = 4256;

fn main(storage_root: pub [u8; 32], trie_proof: trie::TrieProof32<DEPTH8_MAX, 32>) {
    assert(trie_proof.verify_root(storage_root));
}
