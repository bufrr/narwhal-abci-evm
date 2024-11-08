use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex;

use abci::{
    async_api::{
        Consensus as ConsensusTrait, Info as InfoTrait, Mempool as MempoolTrait,
        Snapshot as SnapshotTrait,
    },
    async_trait,
    types::*,
};

use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy_signer::Signer;
use alloy_signer_local::coins_bip39::English;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
use foundry_common::ens::NameOrAddress;
use foundry_evm::revm::primitives::ResultAndState;
use foundry_evm::revm::{
    self,
    db::{CacheDB, EmptyDB},
    primitives::{AccountInfo, CreateScheme, Env, TxEnv},
    Database, DatabaseCommit,
};
use revm::primitives::{ExecutionResult, Output};
use revm::EvmBuilder;
use std::error::Error as StdError;
use alloy::transports::http::Http;

/// The app's state, containing a Revm DB.
// TODO: Should we instead try to replace this with Anvil and implement traits for it?
#[derive(Clone, Debug)]
pub struct State<Db> {
    pub block_height: i64,
    pub app_hash: Vec<u8>,
    pub db: Db,
    pub env: Env,
}

impl Default for State<CacheDB<EmptyDB>> {
    fn default() -> Self {
        Self {
            block_height: 0,
            app_hash: Vec::new(),
            db: CacheDB::new(EmptyDB::default()),
            env: Default::default(),
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct TransactionResult {
    pub out: ExecutionResult,
    pub gas: u64,
    pub logs: Vec<revm::primitives::Log>,
}

impl<Db: Database + DatabaseCommit> State<Db>
where
    Db::Error: StdError + Send + Sync + 'static,
{
    async fn execute(
        &mut self,
        tx: TransactionRequest,
        read_only: bool,
    ) -> eyre::Result<TransactionResult> {
        let result: ResultAndState;
        {
            // Create a new database reference
            let db = &mut self.db;

            // Build new EVM instance using EvmBuilder
            let mut evm = EvmBuilder::default()
                .with_db(&mut *db)
                .with_env(Box::from(self.env.clone()))
                .build();

            // Configure transaction environment
            evm.context.evm.env.tx = TxEnv {
                caller: tx.from.unwrap_or_default(),
                transact_to: tx.to.unwrap_or_else(|| TxKind::Create),
                value: tx.value.unwrap_or_default(),
                data: tx.input.data.clone().unwrap_or_default(),
                gas_limit: tx.gas.unwrap_or(21000),
                gas_price: U256::from(tx.gas_price.unwrap_or_default()),
                gas_priority_fee: Some(U256::from(tx.max_priority_fee_per_gas.unwrap_or_default())),
                blob_hashes: vec![],
                max_fee_per_blob_gas: None,
                authorization_list: None,
                nonce: Some(tx.nonce.unwrap_or_default()),
                chain_id: Some(self.env.cfg.chain_id),
                access_list: vec![],
                optimism: Default::default(),
            };

            // Execute transaction
            result = evm.transact()?;
        }

        // Commit state changes if not read-only
        if !read_only {
            self.db.commit(result.state.clone());
        }

        let rc = result.clone();
        Ok(TransactionResult {
            out: rc.result.clone(),
            gas: rc.result.gas_used(),
            logs: rc.result.logs().into(),
        })
    }
}

pub struct Consensus<Db> {
    pub committed_state: Arc<Mutex<State<Db>>>,
    pub current_state: Arc<Mutex<State<Db>>>,
    pub signer: PrivateKeySigner,
}

impl<Db: Clone> Consensus<Db> {
    pub fn new(state: State<Db>) -> eyre::Result<Self> {
        let committed_state = Arc::new(Mutex::new(state.clone()));
        let current_state = Arc::new(Mutex::new(state));

        let mut signer = MnemonicBuilder::<English>::default()
            .phrase("test test test test test test test test test test test junk")
            .build()
            .map_err(|e| eyre::eyre!("Failed to build signer: {}", e))?;

        signer.set_chain_id(Some(1337));

        Ok(Consensus {
            committed_state,
            current_state,
            signer,
        })
    }
}

#[async_trait]
impl<Db: Clone + Send + Sync + DatabaseCommit + Database> ConsensusTrait for Consensus<Db>
where
    Db::Error: StdError + Send + Sync + 'static,
{
    #[tracing::instrument(skip(self))]
    async fn init_chain(&self, _init_chain_request: RequestInitChain) -> ResponseInitChain {
        ResponseInitChain::default()
    }

    #[tracing::instrument(skip(self))]
    async fn begin_block(&self, _begin_block_request: RequestBeginBlock) -> ResponseBeginBlock {
        ResponseBeginBlock::default()
    }

    #[tracing::instrument(skip(self))]
    async fn deliver_tx(&self, deliver_tx_request: RequestDeliverTx) -> ResponseDeliverTx {
        println!("delivering tx");

        let tx: TransactionRequest = match serde_json::from_slice(&deliver_tx_request.tx) {
            Ok(tx) => tx,
            Err(_) => {
                tracing::error!("could not decode request");
                return ResponseDeliverTx {
                    data: "could not decode request".into(),
                    ..Default::default()
                };
            }
        };

        let wallet = EthereumWallet::from(self.signer.clone());

        let tx_envelope = match tx.build(&wallet).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return ResponseDeliverTx {
                    data: format!("failed to build transaction: {}", e).into(),
                    ..Default::default()
                }
            }
        };

        let receipt = match PROVIDER.send_tx_envelope(tx_envelope).await {
            Ok(pending) => match pending.get_receipt().await {
                Ok(receipt) => receipt,
                Err(e) => {
                    return ResponseDeliverTx {
                        data: format!("failed to get transaction receipt: {}", e).into(),
                        ..Default::default()
                    }
                }
            },
            Err(e) => {
                return ResponseDeliverTx {
                    data: format!("failed to send transaction: {}", e).into(),
                    ..Default::default()
                }
            }
        };

        println!("transaction hash: {:?}", receipt.transaction_hash);
        ResponseDeliverTx {
            data: serde_json::to_vec(&receipt.transaction_hash)
                .unwrap_or_else(|_| b"failed to serialize transaction hash".to_vec()),
            ..Default::default()
        }
    }

    #[tracing::instrument(skip(self))]
    async fn end_block(&self, end_block_request: RequestEndBlock) -> ResponseEndBlock {
        tracing::trace!("ending block");
        let mut current_state = self.current_state.lock().await;
        current_state.block_height = end_block_request.height;
        current_state.app_hash = vec![];
        tracing::trace!("done");

        ResponseEndBlock::default()
    }

    #[tracing::instrument(skip(self))]
    async fn commit(&self, _commit_request: RequestCommit) -> ResponseCommit {
        tracing::trace!("taking lock");
        let current_state = self.current_state.lock().await.clone();
        let mut committed_state = self.committed_state.lock().await;
        *committed_state = current_state;
        tracing::trace!("committed");

        ResponseCommit {
            data: vec![], // (*committed_state).app_hash.clone(),
            retain_height: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Mempool;

#[async_trait]
impl MempoolTrait for Mempool {
    async fn check_tx(&self, _check_tx_request: RequestCheckTx) -> ResponseCheckTx {
        ResponseCheckTx::default()
    }
}

#[derive(Debug, Clone)]
pub struct Info<Db> {
    pub state: Arc<Mutex<State<Db>>>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Query {
    EthCall(TransactionRequest),
    Balance(Address),
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum QueryResponse {
    Tx(TransactionResult),
    Balance(U256),
}

impl QueryResponse {
    pub fn as_tx(&self) -> &TransactionResult {
        match self {
            QueryResponse::Tx(inner) => inner,
            _ => panic!("not a tx"),
        }
    }

    pub fn as_balance(&self) -> U256 {
        match self {
            QueryResponse::Balance(inner) => *inner,
            _ => panic!("not a balance"),
        }
    }
}

#[async_trait]
impl<Db: Send + Sync + Database + DatabaseCommit> InfoTrait for Info<Db>
where
    Db::Error: StdError + Send + Sync + 'static,
{
    async fn info(&self, _info_request: RequestInfo) -> ResponseInfo {
        let state = self.state.lock().await;

        ResponseInfo {
            data: Default::default(),
            version: Default::default(),
            app_version: Default::default(),
            last_block_height: (*state).block_height,
            last_block_app_hash: (*state).app_hash.clone(),
        }
    }

    // replicate the eth_call interface
    async fn query(&self, query_request: RequestQuery) -> ResponseQuery {
        let mut state = self.state.lock().await;

        let query: Query = match serde_json::from_slice(&query_request.data) {
            Ok(q) => q,
            Err(_) => {
                return ResponseQuery {
                    value: "could not decode request".into(),
                    ..Default::default()
                }
            }
        };

        let res = match query {
            Query::Balance(address) => match state.db.basic(address) {
                Ok(Some(account)) => QueryResponse::Balance(account.balance),
                Ok(None) => QueryResponse::Balance(U256::ZERO),
                Err(_) => {
                    return ResponseQuery {
                        value: "database error".into(),
                        ..Default::default()
                    }
                }
            },
            Query::EthCall(mut tx) => {
                match tx.to {
                    Some(addr) => tx.to = Some(addr.into()),
                    _ => panic!("not an address"),
                };

                let result = state.execute(tx, true).await.unwrap();
                QueryResponse::Tx(result)
            }
        };

        ResponseQuery {
            key: query_request.data,
            value: serde_json::to_vec(&res).unwrap_or_default(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot;

impl SnapshotTrait for Snapshot {}

use alloy::transports::http::reqwest::Client;

static PROVIDER: Lazy<Box<dyn Provider<Http<Client>>>> = Lazy::new(|| {
    Box::new(
        ProviderBuilder::new().with_recommended_fillers().on_http(
            "http://213.136.78.134:8545"
                .parse()
                .expect("Invalid provider URL"),
        ),
    )
});
