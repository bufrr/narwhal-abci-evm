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
use futures::SinkExt;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::sleep;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

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

    let mut nonce = provider.get_transaction_count(alice).await?;

    // Connect directly to worker's mempool
    let stream = TcpStream::connect(mempool_address).await?;
    let mut transport = Framed::new(stream, LengthDelimitedCodec::new());

    let tx = TransactionRequest::default()
        .with_to(address!("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
        .with_nonce(nonce)
        .with_chain_id(1337)
        .with_value(value.into())
        .with_gas_limit(21_000)
        .with_max_priority_fee_per_gas(1_000_000_000)
        .with_max_fee_per_gas(20_000_000_000);

    let tx = serde_json::to_string(&tx)?;
    println!("tx_len: {}", tx.len());

    let mut total_count = 0u64;
    let mut count = 0u64;
    let start_time = std::time::Instant::now();
    let mut last_print = start_time;
    let print_interval = Duration::from_secs(1);

    loop {
        transport.send(tx.clone().into()).await?;
        count += 1;
        total_count += 1;

        if count >= 1000 {
            let elapsed = last_print.elapsed();
            if elapsed >= print_interval {
                let overall_tps = total_count as f64 / start_time.elapsed().as_secs_f64();
                let current_tps = count as f64 / elapsed.as_secs_f64();
                println!(
                    "Current: {} tx/s, Average: {} tx/s",
                    Paint::green(&format!("{:.2}", current_tps)),
                    Paint::blue(&format!("{:.2}", overall_tps))
                );
                count = 0;
                last_print = std::time::Instant::now();
            }
        }
    }
}
