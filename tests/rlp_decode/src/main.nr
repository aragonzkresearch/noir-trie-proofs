use dep::trie;
use dep::trie::rlp;

fn main(input: [u8; 532]) {
    let rlp_list: rlp::RLP_List<trie::MAX_NUM_FIELDS> = rlp::decode1_small_lis(input);
    assert(rlp_list.num_fields == 17);
}
