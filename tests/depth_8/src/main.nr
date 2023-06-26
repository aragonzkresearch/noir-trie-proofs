use dep::trie;
global DEPTH8_MAX: Field = 4256;

fn main(root_hash: pub [u8; 32], trie_proof: trie::TrieProof32<DEPTH8_MAX, 32>) {
    assert(trie::verify_storage_proof(root_hash, trie_proof));
}
