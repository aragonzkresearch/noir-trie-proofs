use dep::trie;
use dep::trie::rlp;

 fn main(input: [u8; 532])
{
    let rlp_list: (Field, [Field; trie::MAX_NUM_FIELDS], [Field; trie::MAX_NUM_FIELDS], [Field; trie::MAX_NUM_FIELDS]) = rlp::decode1(input);
    constrain rlp_list.0 == 17;
}
