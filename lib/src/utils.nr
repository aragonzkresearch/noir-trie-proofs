/// Fills destination array with content of source array starting from the starting position.
///
/// # Arguments
/// * `dest` - Destination array
/// * `src` - Source array
/// * `offset` - Offset in source array 
pub(crate) fn memcpy<N, M>(dest: &mut [u8; N], src: [u8; M], offset: u64)
{
    for i in 0..N
    {
        (*dest)[i] = src[offset + i];
    }
}

/// Verifies that specified number of elements from a subarray match elements from the array
/// at specified offset.
///
/// # Arguments
/// * `subarray` - Array to be verified
/// * `array` - Array to be verified against
/// * `len` - Number of elements to be verified
/// * `offset` - Offset in `array`
pub(crate) fn assert_subarray<N, M>(subarray: [u8; N], array: [u8; M], len: u64, offset: u64)
{
    for i in 0..N
    {
        if i < len {
            assert(subarray[i] == array[offset + i], "Arrays do not match at specified offset");
        }
    }
}

/// Byte-to-nibble converter. Returns a pair of two nibbles.
///
/// # Arguments
/// * `b` - Byte
pub(crate) fn byte_to_nibbles(b: u8) -> (u8, u8)
{
    let upper = b >> 4;
    let lower = b - 16*upper;

    (upper, lower)
}

/// Function for expressing a big-endian byte array as a right-padded one.
/// Returns a right-padded byte array together with the actual byte length of the number.
///
/// # Arguments
/// * `in_value` - Byte array representing a number in big-endian form.
pub(crate) fn byte_value<N>(in_value: [u8; N]) -> ([u8; N], u64)
{
    let mut value_length = 0;

    for i in 0..N
    {
        let num_bytes_ind = (value_length == 0) as u64;
        let byte_ind = (in_value[i] != 0) as u64;
        value_length = num_bytes_ind * byte_ind * (N - i) + (1 - num_bytes_ind) * value_length;
    }

    let value = left_byte_shift(in_value, N - value_length);

    (value, value_length)
}

/// Left-shift for byte arrays
/// Returns an appropriately shifted byte array.
///
/// # Arguments
/// * `input` - Byte array
/// * `n` - Amount to left-shift elements by
///
/// # Quirks
/// The empty slots are set to 0.
pub(crate) fn left_byte_shift<N>(input: [u8; N], n: u64) -> [u8; N]
{
    let mut out = [0; N];

    for i in 0..N
    {
        // Restrict indices to be shifted, i.e. ∀i: i+n < N, out[i] ← input[i + n].
        let index_ind = (((i+n) as u32) < (N as u32)) as u64;
        out[i] = (index_ind as u8)*input[index_ind*(i+n)];
    }

    out
}