use alloy::primitives::{
    utils::{format_units, parse_units},
    Address,
};
use evm_abci::types::{Query, QueryResponse};
use eyre::Result;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
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
use tokio::sync::Semaphore;
use tokio::time::sleep;

static ALICE: Lazy<Address> = Lazy::new(|| {
    "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        .parse::<Address>()
        .unwrap()
});
static BOB: Lazy<Address> = Lazy::new(|| {
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
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

async fn send_transaction(host: &str, from: Address, to: Address, value: U256, nonce: u64) -> Result<()> {
    println!("from address: {}", from);

    // Build a transaction to send 100 wei from Alice to Bob.
    // The `from` field is automatically filled to the first signer's address (Alice).
    let tx = TransactionRequest::default()
        .with_to(to)
        .with_nonce(nonce)
        .with_chain_id(1337)
        .with_value(value)
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
    let host = "http://213.136.78.134:3009";


    let value = parse_units("1", "wei")?;
    let mut signer = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;

    signer.set_chain_id(Some(1337));

    let alice = signer.address();

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http("http://213.136.78.134:8545".parse()?);

    // Create two users, Alice and Bob.
    //let alice = wallet.address().clone();
    let mut nonce = provider.get_transaction_count(alice).await?;

    let semaphore = Arc::new(Semaphore::new(10));
    let client = reqwest::Client::new();
    let mut count = 0;


    loop {
        let permit = semaphore.clone().acquire_owned().await?;
        let client = client.clone();
        let current_nonce = nonce;
        nonce += 1;
        count += 1;
        println!("nonce: {}", nonce);

        tokio::spawn(async move {
            let tx = TransactionRequest::default()
                .with_to(address!("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
                .with_nonce(current_nonce)
                .with_chain_id(1337)
                .with_value(value.into())
                .with_gas_limit(21_000)
                .with_max_priority_fee_per_gas(1_000_000_000)
                .with_max_fee_per_gas(20_000_000_000);

            let tx = serde_json::to_string(&tx)?;

            client
                .get(format!("{}/broadcast_tx", host))
                .query(&[("tx", tx)])
                .send()
                .await?;

            drop(permit);
            Ok::<_, eyre::Error>(())
        });

        sleep(Duration::from_millis(200)).await;
    }

    println!("---");

    sleep(Duration::from_secs(5)).await;


    //send_transaction(host, alice, *BOB, value.into(), nonce).await?;

    println!("---");

    Ok(())
}
