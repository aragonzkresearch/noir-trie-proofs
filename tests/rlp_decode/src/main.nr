use dep::trie;
use dep::trie::rlp;

 fn main(input: [u8; 532])
{
    let rlp_list = rlp::decode1(input);
    constrain rlp_list.num_elements == 17;
}
