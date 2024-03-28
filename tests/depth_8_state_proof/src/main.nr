use dep::trie::{trie_proof::TrieProof, const::MAX_ACCOUNT_STATE_LENGTH};
use dep::std::hash::keccak256;

global DEPTH8_MAX: Field = 4256;

fn main(
    state_root: pub [u8; 32],
    state_proof: TrieProof<20, DEPTH8_MAX, MAX_ACCOUNT_STATE_LENGTH>
) {
    assert(state_proof.verify_state_root(state_root));
}
