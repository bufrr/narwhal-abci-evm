use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::providers::{Provider, ProviderBuilder};
use log::info;
use std::hash::Hash;
use std::net::SocketAddr;
use tokio::sync::mpsc::Receiver;
use tokio::sync::oneshot::Sender as OneShotSender;
use tokio::time::{sleep, Duration};

// Narwhal types
use narwhal_crypto::Digest;
use narwhal_primary::Certificate;

use alloy::rpc::types::TransactionRequest;
use alloy::transports::http::Http;
use alloy_signer::Signer;
use alloy_signer_local::coins_bip39::English;
use alloy_signer_local::MnemonicBuilder;

/// The engine drives the ABCI Application by concurrently polling for:
/// 1. Calling the BeginBlock -> DeliverTx -> EndBlock -> Commit event loop on the ABCI App on each Bullshark
///    certificate received. It will also call Info and InitChain to initialize the ABCI App if
///    necessary.
/// 2. Processing Query & Broadcast Tx messages received from the Primary's ABCI Server API and forwarding them to the
///    ABCI App via a Tendermint protobuf client.
pub struct Engine {
    pub store_path: String,
}

impl Engine {
    pub fn new(store_path: &str) -> Self {
        Self {
            store_path: store_path.to_string(),
        }
    }

    /// Receives an ordered list of certificates and apply any application-specific logic.
    pub async fn run(&mut self, mut rx_output: Receiver<Certificate>) -> eyre::Result<()> {
        loop {
            tokio::select! {
                Some(certificate) = rx_output.recv() => {
                    info!("rx_output len: {}", rx_output.len());
                    let store_path = self.store_path.clone();
                    tokio::spawn(async move {
                        handle_cert(certificate, store_path).await.expect("handle_cert panic");
                    });
                },
                else => {
                    println!("loop exit!!!");
                    break;
                },
            }
        }

        Ok(())
    }

    /// On each new certificate, increment the block height to proposed and run through the
    /// BeginBlock -> DeliverTx for each tx in the certificate -> EndBlock -> Commit event loop.
    async fn handle_cert(&self, certificate: Certificate) -> eyre::Result<()> {
        // Reconstruct batches from certificate
        let futures: Vec<_> = certificate
            .header
            .payload
            .into_iter()
            .map(|(digest, worker_id)| self.reconstruct_batch(digest, worker_id))
            .collect();

        let batches = futures::future::join_all(futures).await;

        // Process each batch
        for batch in batches {
            let batch = batch?;
            self.process_batch(batch).await?;
        }

        info!("Certificate processed");
        Ok(())
    }

    async fn process_batch(&self, batch: Vec<u8>) -> eyre::Result<()> {
        // Deserialize and process the batch
        match bincode::deserialize(&batch) {
            Ok(WorkerMessage::Batch(txs)) => {
                for tx in txs {
                    self.process_transaction(tx).await?;
                }
                Ok(())
            }
            _ => eyre::bail!("Unrecognized message format"),
        }
    }

    /// Opens a RocksDB handle to a Worker's database and tries to read the batch
    /// stored at the provided certificate's digest.
    async fn reconstruct_batch(&self, digest: Digest, worker_id: u32) -> eyre::Result<Vec<u8>> {
        let max_attempts = 3;
        let backoff_ms = 500;

        for attempt in 0..max_attempts {
            // Open the database to each worker
            let db = rocksdb::DB::open_for_read_only(
                &rocksdb::Options::default(),
                self.worker_db(worker_id),
                true,
            )?;

            // Query the db
            let key = digest.to_vec();
            match db.get(&key)? {
                Some(res) => return Ok(res),
                None if attempt < max_attempts - 1 => {
                    println!(
                        "digest {} not found, retrying in {}ms",
                        digest,
                        backoff_ms * (attempt + 1)
                    );
                    sleep(Duration::from_millis(backoff_ms * (attempt + 1))).await;
                    continue;
                }
                None => eyre::bail!(
                    "digest {} not found after {} attempts",
                    digest,
                    max_attempts
                ),
            }
        }

        unreachable!()
    }

    async fn process_transaction(&self, tx: Transaction) -> eyre::Result<()> {
        match serde_json::from_slice::<TransactionRequest>(&tx) {
            Ok(tx) => {
                info!("tx request");
                let mut signer = MnemonicBuilder::<English>::default()
                    .phrase("test test test test test test test test test test test junk")
                    .build()
                    .map_err(|e| eyre::eyre!("Failed to build signer: {}", e))
                    .unwrap();

                signer.set_chain_id(Some(1337));
                let wallet = EthereumWallet::from(signer);

                let tx_envelope = tx.build(&wallet).await.unwrap();
                match PROVIDER.send_tx_envelope(tx_envelope).await {
                    Ok(_) => {
                        info!("Transaction sent successfully");
                    }
                    Err(e) => {
                        info!("Failed to send transaction: {}", e);
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                info!("could not decode request {}", e);
                return Ok(());
            }
        };
        Ok(())
    }

    /// Helper function for getting the database handle to a worker associated
    /// with a primary (e.g. Primary db-0 -> Worker-0 db-0-0, Wroekr-1 db-0-1 etc.)
    fn worker_db(&self, id: u32) -> String {
        format!("{}-{}", self.store_path, id)
    }
}

// Helpers for deserializing batches, because `narwhal::worker` is not part
// of the public API. TODO -> make a PR to expose it.
pub type Transaction = Vec<u8>;
pub type Batch = Vec<Transaction>;
#[derive(serde::Deserialize)]
pub enum WorkerMessage {
    Batch(Batch),
}

use alloy::transports::http::reqwest::Client;
use once_cell::sync::Lazy;

static PROVIDER: Lazy<Box<dyn Provider<Http<Client>>>> = Lazy::new(|| {
    Box::new(
        ProviderBuilder::new().with_recommended_fillers().on_http(
            "http://127.0.0.1:8545"
                .parse()
                .expect("Invalid provider URL"),
        ),
    )
});

async fn reconstruct_batch(
    digest: Digest,
    worker_id: u32,
    store_path: String,
) -> eyre::Result<Vec<u8>> {
    let max_attempts = 3;
    let backoff_ms = 500;
    let db_path = format!("{}-{}", store_path, worker_id);
    // Open the database to each worker
    let db = rocksdb::DB::open_for_read_only(&rocksdb::Options::default(), db_path, true)?;

    for attempt in 0..max_attempts {
        // Query the db
        let key = digest.to_vec();
        match db.get(&key)? {
            Some(res) => return Ok(res),
            None if attempt < max_attempts - 1 => {
                println!(
                    "digest {} not found, retrying in {}ms",
                    digest,
                    backoff_ms * (attempt + 1)
                );
                sleep(Duration::from_millis(backoff_ms * (attempt + 1))).await;
                continue;
            }
            None => eyre::bail!(
                "digest {} not found after {} attempts",
                digest,
                max_attempts
            ),
        }
    }
    unreachable!()
}

async fn handle_cert(certificate: Certificate, store_path: String) -> eyre::Result<()> {
    // Reconstruct batches from certificate
    let futures: Vec<_> = certificate
        .header
        .payload
        .into_iter()
        .map(|(digest, worker_id)| reconstruct_batch(digest, worker_id, store_path.clone()))
        .collect();

    let batches = futures::future::join_all(futures).await;

    for batch in batches {
        let batch = batch?;
        process_batch(batch).await?;
    }
    Ok(())
}

async fn process_batch(batch: Vec<u8>) -> eyre::Result<()> {
    // Deserialize and process the batch
    match bincode::deserialize(&batch) {
        Ok(WorkerMessage::Batch(txs)) => {
            info!("txs len: {}", txs.len());
            Ok(())
        }
        _ => eyre::bail!("Unrecognized message format"),
    }
}
