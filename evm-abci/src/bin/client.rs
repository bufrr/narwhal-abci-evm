use alloy::primitives::{
    utils::{format_units, parse_units},
    Address,
};
use evm_abci::types::{Query, QueryResponse};
use eyre::Result;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use yansi::Paint;
use alloy::{
    network::{TransactionBuilder, EthereumWallet},
    primitives::U256,
    providers::{Provider, ProviderBuilder, WalletProvider},
    rpc::types::TransactionRequest,
};
use alloy::network::{Ethereum, NetworkWallet};
use alloy::transports::http::reqwest::Url;
use alloy_primitives::address;
use alloy_signer::Signer;
use alloy_signer_local::{MnemonicBuilder, coins_bip39::English};

static ALICE: Lazy<Address> = Lazy::new(|| {
    "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        .parse::<Address>()
        .unwrap()
});
static BOB: Lazy<Address> = Lazy::new(|| {
    "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        .parse::<Address>()
        .unwrap()
});
static CHARLIE: Lazy<Address> = Lazy::new(|| {
    "0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
        .parse::<Address>()
        .unwrap()
});

static ADDRESS_TO_NAME: Lazy<HashMap<Address, &'static str>> = Lazy::new(|| {
    let mut address_to_name = HashMap::new();
    address_to_name.insert(*ALICE, "Alice");
    address_to_name.insert(*BOB, "Bob");
    address_to_name.insert(*CHARLIE, "Charlie");

    address_to_name
});

fn get_readable_eth_value(value: U256) -> Result<f64> {
    let value_string = format_units(value, "ether")?;
    Ok(value_string.parse::<f64>()?)
}

async fn query_balance(host: &str, address: Address) -> Result<()> {
    let query = Query::Balance(address);
    let query = serde_json::to_string(&query)?;

    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/abci_query", host))
        .query(&[("data", query), ("path", "".to_string())])
        .send()
        .await?;

    let val = res.bytes().await?;
    let val: QueryResponse = serde_json::from_slice(&val)?;
    let val = val.as_balance();
    let readable_value = get_readable_eth_value(val)?;
    let name = ADDRESS_TO_NAME.get(&address).unwrap();
    println!(
        "{}'s balance: {}",
        Paint::new(name).bold(),
        Paint::green(&format!("{} ETH", &readable_value)).bold()
    );
    Ok(())
}

async fn query_all_balances(host: &str) -> Result<()> {
    println!("Querying balances from {}:", Paint::new(host).bold());

    query_balance(host, *ALICE).await?;
    query_balance(host, *BOB).await?;
    query_balance(host, *CHARLIE).await?;

    Ok(())
}

async fn send_transaction(host: &str, from: Address, to: Address, value: U256) -> Result<()> {
    let mut signer = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;

    signer.set_chain_id(Some(1337));


    let wallet = EthereumWallet::from(signer.clone());
    let alice = signer.address();
    println!("Alice's address: {}", alice);

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http("http://213.136.78.134:8545".parse()?);

    // Create two users, Alice and Bob.
    //let alice = wallet.address().clone();
    let bob = address!("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    let nonce = provider.get_transaction_count(alice).await?;

    // Build a transaction to send 100 wei from Alice to Bob.
    // The `from` field is automatically filled to the first signer's address (Alice).
    let tx = TransactionRequest::default()
        .with_to(bob)
        .with_nonce(nonce)
        .with_chain_id(1337)
        .with_value(U256::from(100))
        .with_gas_limit(21_000)
        .with_max_priority_fee_per_gas(1_000_000_000)
        .with_max_fee_per_gas(20_000_000_000);


    let tx = serde_json::to_string(&tx)?;

    let client = reqwest::Client::new();
    client
        .get(format!("{}/broadcast_tx", host))
        .query(&[("tx", tx)])
        .send()
        .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // the ABCI port on the various narwhal primaries
    let host_1 = "http://213.136.78.134:3002";
    let host_2 = "http://213.136.78.134:3009";
    let host_3 = "http://213.136.78.134:3016";

    let value = parse_units("1", "ether")?;

    // Query initial balances from host_1
    query_all_balances(host_1).await?;

    println!("---");

    // Send conflicting transactions
    println!(
        "{} sends {} transactions:",
        Paint::new("Alice").bold(),
        Paint::red("conflicting").bold()
    );
    send_transaction(host_2, *ALICE, *BOB, value.into()).await?;
    //send_transaction(host_3, *ALICE, *CHARLIE, value.into()).await?;

    println!("---");

    println!("Waiting for consensus...");
    // Takes ~5 seconds to actually apply the state transition?
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // println!("---");
    // 
    // // Query final balances from host_2
    // query_all_balances(host_2).await?;
    // 
    // println!("---");
    // 
    // // Query final balances from host_3
    // query_all_balances(host_3).await?;

    Ok(())
}
