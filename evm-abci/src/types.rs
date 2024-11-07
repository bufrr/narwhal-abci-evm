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

use alloy::primitives::{Address, Bytes, TxKind, U256};
use alloy::rpc::types::TransactionRequest;
use foundry_common::ens::NameOrAddress;
use foundry_evm::revm::{
    self,
    db::{CacheDB, EmptyDB},
    primitives::{AccountInfo, CreateScheme, Env, TxEnv},
    Database, DatabaseCommit,
};
use revm::primitives::{ExecutionResult, Output};
use revm::EvmBuilder;
use std::error::Error as StdError;
use foundry_evm::revm::primitives::ResultAndState;

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
}

impl<Db: Clone> Consensus<Db> {
    pub fn new(state: State<Db>) -> Self {
        let committed_state = Arc::new(Mutex::new(state.clone()));
        let current_state = Arc::new(Mutex::new(state));

        Consensus {
            committed_state,
            current_state,
        }
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
        tracing::trace!("delivering tx");
        let mut state = self.current_state.lock().await;

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

        let result = match state.execute(tx, false).await {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("execution failed: {}", e);
                return ResponseDeliverTx {
                    data: format!("execution failed: {}", e).into(),
                    ..Default::default()
                };
            }
        };

        ResponseDeliverTx {
            data: serde_json::to_vec(&result).unwrap(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::network::TransactionBuilder;
    use alloy::primitives::utils::parse_units;
    // use ethers::prelude::*;

    #[tokio::test]
    async fn run_and_query_tx() {
        let val = parse_units("1", 18).unwrap();
        let alice = Address::random();
        let bob = Address::random();

        let mut state = State::default();

        // give alice some money
        state.db.insert_account_info(
            alice,
            AccountInfo {
                balance: val.into(),
                ..Default::default()
            },
        );

        // make the tx
        let mut tx = TransactionRequest::default()
            .from(alice)
            .to(bob)
            .input(vec![1, 2, 3, 4, 5].into())
            .value(val.into());
        tx.set_gas_price(0);
        tx.set_gas_limit(21000);

        // Send it over an ABCI message

        let consensus = Consensus::new(state);

        let req = RequestDeliverTx {
            tx: serde_json::to_vec(&tx).unwrap(),
        };
        let res = consensus.deliver_tx(req).await;
        let res: TransactionResult = serde_json::from_slice(&res.data).unwrap();
        // tx passed

        match res.out {
            ExecutionResult::Success { reason, .. } => {
                assert_eq!(reason, revm::primitives::SuccessReason::Stop);
            }
            ExecutionResult::Revert { .. } => {
                panic!("Transaction reverted");
            }
            ExecutionResult::Halt { .. } => {
                panic!("Transaction halted");
            }
        }

        // now we query the state for bob's balance
        let info = Info {
            state: consensus.current_state.clone(),
        };
        let res = info
            .query(RequestQuery {
                data: serde_json::to_vec(&Query::Balance(bob)).unwrap(),
                ..Default::default()
            })
            .await;
        let res: QueryResponse = serde_json::from_slice(&res.value).unwrap();
        let balance = res.as_balance();
        assert_eq!(balance, val.into());
    }
}
