use alloy::network::{Ethereum, NetworkWallet};
use alloy::primitives::{
    utils::{format_units, parse_units},
    Address,
};
use alloy::transports::http::reqwest::Url;
use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    primitives::U256,
    providers::{Provider, ProviderBuilder, WalletProvider},
    rpc::types::TransactionRequest,
};
use alloy_primitives::address;
use alloy_signer::Signer;
use alloy_signer_local::{coins_bip39::English, MnemonicBuilder};
use evm_abci::types::{Query, QueryResponse};
use eyre::Result;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use futures::SinkExt;

use yansi::Paint;

async fn send_transaction(
    host: &str,
    from: Address,
    to: Address,
    value: U256,
    nonce: u64,
) -> Result<()> {
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
    // worker-0 memory pool address
    let mempool_address: SocketAddr = "127.0.0.1:3005".parse()?;
    let value = parse_units("1", "wei")?;
    let mut signer = MnemonicBuilder::<English>::default()
        .phrase("test test test test test test test test test test test junk")
        .build()?;

    signer.set_chain_id(Some(1337));

    let alice = signer.address();
    println!("alice: {}", alice);

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .on_http("http://127.0.0.1:8545".parse()?);

    // Create two users, Alice and Bob.
    //let alice = wallet.address().clone();
    let mut nonce = provider.get_transaction_count(alice).await?;

    let semaphore = Arc::new(Semaphore::new(10));
    let client = reqwest::Client::new();
    let mut count = 0;

    // Connect directly to worker's mempool
    let stream = TcpStream::connect(mempool_address).await?;
    let mut transport = Framed::new(stream, LengthDelimitedCodec::new());

    loop {
        let permit = semaphore.clone().acquire_owned().await?;
        let client = client.clone();
        let current_nonce = nonce;
        nonce += 1;
        count += 1;
        println!("nonce: {}", nonce);

        let tx = TransactionRequest::default()
            .with_to(address!("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
            .with_nonce(current_nonce)
            .with_chain_id(1337)
            .with_value(value.into())
            .with_gas_limit(21_000)
            .with_max_priority_fee_per_gas(1_000_000_000)
            .with_max_fee_per_gas(20_000_000_000);

        let tx = serde_json::to_string(&tx)?;


        // Send transaction directly to mempool
        transport.send(tx.into()).await?;

        drop(permit);

        sleep(Duration::from_millis(100)).await;
    }

    println!("---");

    sleep(Duration::from_secs(5)).await;

    //send_transaction(host, alice, *BOB, value.into(), nonce).await?;

    println!("---");

    Ok(())
}
