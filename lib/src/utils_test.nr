use crate::utils::{
    memcpy,
    assert_subarray,
    byte_value
};

#[test]
fn test_memcpy()
{
    let mut dest = [0; 3];
    let src = [1, 2, 3, 4, 5];
    memcpy(&mut dest, src, 2);
    assert(dest == [3, 4, 5]);
}

#[test]
fn test_arrays_equal()
{
    let subarray = [2, 3];
    let array = [1, 2, 3];
    assert_subarray(subarray, array, 2, 1);
}

#[test(should_fail_with_message = "Arrays do not match at specified offset")]
fn test_arrays_equal_fail()
{
    let subarray = [1, 2, 3];
    let array = [1, 2, 4];
    assert_subarray(subarray, array, 2, 1);
}

#[test]
fn byte_value_test()
{
    let test0 = byte_value([0,0,0,1,2,3]);
    assert((test0.0 == [1,2,3,0,0,0]) & (test0.1 == 3));

    let test1 = byte_value([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,0,0,0]);
    assert((test1.0 == [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,0,0,0]) & (test1.1 == 32));

    let test2 = byte_value([0,0,0,0,0,0,0,0,0,0,11,12,13,14,15,16,17,18,19,20,0,0,0,0,0,0,0,0,0,0,0,0]);
    assert((test2.0 == [11,12,13,14,15,16,17,18,19,20,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]) & (test2.1 == 22));
}