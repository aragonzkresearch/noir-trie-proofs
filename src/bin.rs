use clap::{Parser, Subcommand};

use ethers::prelude::*;
use noir_trie_proofs::*;

#[derive(Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help(true))]
struct Cli
{
    /// Type of proof to fetch: storage_proof or state_proof
    #[command(subcommand)]
    proof_type: Commands,
    /// URL of JSON-RPC supporting Ethereum node
    #[arg(short, long, value_name = "RPC_URL", global = true, env)]
    rpc_url: Option<String>,
    /// Maximum allowable depth of proof
    #[arg(short, long, value_name = "MAX_DEPTH", global = true)]
    max_depth: Option<usize>,
    /// Block number. If left unspecified, the latest block number is used.
    #[arg(short, long, value_name = "BLOCK_NUMBER", global = true)]
    block_number: Option<u64>,
    /// Optional name of trie root in Toml output.
    #[arg(long, value_name = "ROOT_NAME", global = true)]
    root_name: Option<String>,
    /// Optional name of trie proof in Toml output.
    #[arg(long, value_name = "PROOF_NAME", global = true)]
    proof_name: Option<String>
}

#[derive(Subcommand)]
enum Commands
{
    /// Fetch storage proof
    StorageProof
    {
        /// Address of the account from which a storage proof is retrieved
        #[arg(short, long, value_name = "ADDRESS")]
        address: Address,
        /// Key of the storage slot for which a storage proof is retrieved
        #[arg(short, long, value_name = "KEY")]
        key: H256,
    },
    /// Fetch state proof
    StateProof
    {
        /// Address of the account whose state proof is retrieved
        #[arg(short, long, value_name = "ADDRESS")]
        address: Address,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>
{
    // Parse args
    let cli = Cli::parse();
    // Max depth and RPC URL *must* be specified
    let max_depth = cli.max_depth.ok_or("--max-depth must be specified!")?;
    let rpc_url = cli.rpc_url.ok_or("--rpc-url must be specified!")?;

    // Specify provider
    let provider = Provider::<Http>::try_from(rpc_url)?;

    // Process block number
    let block_number: U64 = match cli.block_number {
        Some(bn) => bn.into(),
        None => provider.get_block_number().await?,
    };

    // Cases for different proof types
    match cli.proof_type {
        Commands::StorageProof { address, key } => {
            let (storage_root, storage_proof) =
                fetch_storage_proof(provider, block_number, key, address, max_depth).await?;

            println!("{} = {:#04x?}\n", cli.root_name.unwrap_or("storage_root".to_string()), storage_root);
            println!("{}", storage_proof.to_toml_string(&cli.proof_name.unwrap_or("storage_proof".to_string())));
        }
        Commands::StateProof { address } => {
            let (state_root, state_proof) =
                fetch_state_proof(provider, block_number, address, max_depth).await?;

            println!("{} = {:#04x?}\n", cli.root_name.unwrap_or("state_root".to_string()), state_root);
            println!("{}", state_proof.to_toml_string(&cli.proof_name.unwrap_or("state_proof".to_string())));
        }
    };

    Ok(())
}
