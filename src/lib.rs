use ethers::prelude::*;
use ethers::utils::rlp;

/// Maximum length of a state or storage trie node in bytes
const MAX_TRIE_NODE_LENGTH: usize = 532;

/// Maximum size of the value in a storage slot
const MAX_STORAGE_VALUE_LENGTH: usize = 32;

/// Maximum size of the RLP-encoded list representing an account state
const MAX_ACCOUNT_STATE_LENGTH: usize = 134;

/// Trie proof struct mirroring the equivalent Noir code
pub struct TrieProof
{
    /// Unhashed key
    key: Vec<u8>,
    /// Flat RLP-encoded proof with appropriate padding
    proof: Vec<u8>,
    /// Actual proof depth
    depth: usize,
    /// The value resolved by the proof
    value: Vec<u8>,
}

impl TrieProof
{
    /// Proof Toml string formatter. Returns a string with the table entries corresponding to a `TrieProof`.
    ///
    /// # Arguments
    /// * `tp` - A reference to a trie proof
    pub fn to_toml_string(&self, proof_name: &str) -> String
    {
        // Print Toml string
        format!(
            "[{}]\nkey = {:#04x?}\nproof = {:#04x?}\ndepth = {:#04x?}\nvalue = {:#04x?}",
            proof_name, self.key, self.proof, self.depth, self.value
        )
    }
}

/// State proof fetcher and preprocessor. Returns a pair consisting of the state root as a byte vector and the preprocessed state proof.
///
/// # Arguments
/// * `provider` - Provider for interacting with Ethereum JSON RPC API
/// * `block_number` - Block number with respect to which the state proof is retrieved
/// * `address` - Address of the account whose state proof is retrieved
/// * `max_depth` - Maximum admissible depth of the state proof
pub async fn fetch_state_proof<T: JsonRpcClient>(
    provider: Provider<T>,
    block_number: U64,
    address: Address,
    max_depth: usize,
) -> Result<(Vec<u8>, TrieProof), Box<dyn std::error::Error>>
{
    // Call eth_getProof
    let eip1186pr = provider
        .get_proof(address, vec![], Some(BlockId::from(block_number)))
        .await?;

    // Pick out state proof
    let state_proof = eip1186pr.account_proof;

    // ...and state root, for which we need to fetch the current block
    let block: Block<H256> = provider
        .get_block(block_number)
        .await?
        .ok_or(format!("Could not fetch block number {}", block_number))?;
    let state_root = block.state_root.as_bytes().to_vec();

    // Extract value from proof.
    let value = rlp::Rlp::new(
        state_proof
            .last() // Terminal proof node
            .ok_or("State proof empty")?,
    ) // Proof should have been non-empty
        .as_list::<Vec<u8>>()?
        .last() // Extract value
        .ok_or("RLP list empty")?
        .to_vec();

    // Preprocess state proof
    let preproc_proof = preprocess_proof(
        state_proof.clone(),
        address.as_bytes().to_vec(),
        value,
        max_depth,
        MAX_TRIE_NODE_LENGTH,
        MAX_ACCOUNT_STATE_LENGTH,
    )?;

    Ok((state_root, preproc_proof))
}

/// Storage proof fetcher and preprocessor. Returns a pair consisting of the storage root as a byte vector the preprocessed storage root.
///
/// # Arguments
/// * `provider` - Provider for interacting with Ethereum JSON RPC API
/// * `block_number` - Block number with respect to which the storage proof is retrieved
/// * `address` - Address of the account from which the storage proof is retrieved
/// * `key` - 32-byte key of the storage slot for which the storage proof is retreieved
/// * `max_depth` - Maximum admissible depth of the storage proof
pub async fn fetch_storage_proof<T: JsonRpcClient>(
    provider: Provider<T>,
    block_number: U64,
    key: H256,
    address: Address,
    max_depth: usize,
) -> Result<(Vec<u8>, TrieProof), Box<dyn std::error::Error>>
{
    // Call eth_getProof
    let eip1186pr = provider
        .get_proof(address, vec![key], Some(BlockId::from(block_number)))
        .await?;

    // Pick out storage proof
    let storage_proof = eip1186pr
        .storage_proof
        .get(0)
        .ok_or("No storage proof returned")?;

    // ...and storage root
    let storage_root = eip1186pr.storage_hash.as_bytes().to_vec();

    // Extract value as big endian byte array
    let mut value = [0; 32];
    storage_proof.value.to_big_endian(&mut value);

    // Preprocess storage proof
    let preproc_proof = preprocess_proof(
        storage_proof.clone().proof,
        key.as_bytes().to_vec(),
        value.to_vec(),
        max_depth,
        MAX_TRIE_NODE_LENGTH,
        MAX_STORAGE_VALUE_LENGTH,
    )?;

    Ok((storage_root, preproc_proof))
}

/// Trie proof preprocessor. Returns a proof suitable for use in a Noir program using the noir-trie-proofs library.
/// Note: Depending on the application, the `value` field of the struct may have to be further processed, e.g.
/// left-padded to 32 bytes for storage proofs.
///
/// # Arguments
/// * `proof` - Trie proof as a vector of `Bytes`
/// * `key` - Byte vector of the key the trie proof resolves
/// * `value` - Value the key resolves to as a byte vector
/// * `max_depth` - Maximum admissible depth of the trie proof
/// * `max_node_len` - Maximum admissible length of a node in the proof
/// * `max_value_len` - Maximum admissible length of value (in bytes)
pub fn preprocess_proof(
    proof: Vec<Bytes>,
    key: Vec<u8>,
    value: Vec<u8>,
    max_depth: usize,
    max_node_len: usize,
    max_value_len: usize,
) -> Result<TrieProof, Box<dyn std::error::Error>>
{
    // Depth of trie proof
    let depth = proof.len();

    // Padded and flattened proof
    let padded_proof = proof
        .clone()
        .into_iter()
        .map(|b| b.to_vec()) // Convert Bytes to Vec<u8>
        .chain({
            let depth_excess = if depth <= max_depth
            {
                Ok(max_depth - depth)
            } else {
                Err(format!(
                    "The depth of this proof ({}) exceeds the maximum depth specified ({})!",
                    depth, max_depth
                ))
            }?;
            // Append with empty nodes to fill up to depth MAX_DEPTH
            vec![vec![]; depth_excess]
        })
        .map(|mut v| {
            let node_len = v.len();
            let len_excess = if node_len <= max_node_len
            {
                Ok(max_node_len - node_len)
            } else {
                Err("Node length cannot exceed the given maximum.")
            }
            .unwrap();
            // Then pad each node up to length MAX_NODE_LEN
            v.append(&mut vec![0; len_excess]);
            v
        })
        .flatten()
        .collect::<Vec<u8>>(); // And flatten

    // Left-pad value with zeros
    let padded_value = left_pad(&value, max_value_len)?;

    Ok(TrieProof {
        key,
        proof: padded_proof,
        depth,
        value: padded_value,
    })
}

/// Function for left padding a byte vector with zeros. Returns the padded vector.
///
/// # Arguments
/// * `v` - Byte vector
/// * `max_len` - Desired size of padded vector
fn left_pad(v: &Vec<u8>, max_len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>>
{
    if v.len() > max_len
    {
        Err(format!("The vector exceeds its maximum expected dimensions.").into())
    } else {
        let mut v_r = v.clone();
        let mut v_l = vec![0u8; max_len - v.len()];

        v_l.append(&mut v_r);

        Ok(v_l)
    }
}
