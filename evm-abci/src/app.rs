use crate::{Consensus, Info, Mempool, Snapshot, State};
use foundry_evm::revm::db::{CacheDB, EmptyDB};
use std::sync::Arc;
use alloy_primitives::utils::parse_ether;
use alloy_signer::Signer;
use alloy_signer_local::coins_bip39::English;
use alloy_signer_local::MnemonicBuilder;
use foundry_evm::revm::primitives::AccountInfo;
use tokio::sync::Mutex;

pub struct App<Db> {
    pub mempool: Mempool,
    pub snapshot: Snapshot,
    pub consensus: Consensus<Db>,
    pub info: Info<Db>,
}

impl Default for App<CacheDB<EmptyDB>> {
    fn default() -> Self {
        Self::new(false)
    }
}

impl App<CacheDB<EmptyDB>> {
    pub fn new(demo: bool) -> Self {
        let mut state = State {
            db: CacheDB::new(EmptyDB::default()),
            block_height: Default::default(),
            app_hash: Default::default(),
            env: Default::default(),
        };

        if demo {
            state.db.insert_account_info(
                "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .parse()
                    .unwrap(),
                AccountInfo {
                    balance: parse_ether("1.5").unwrap(),
                    ..Default::default()
                },
            );
        }

        let committed_state = Arc::new(Mutex::new(state.clone()));
        let current_state = Arc::new(Mutex::new(state));

        let mut signer = MnemonicBuilder::<English>::default()
            .phrase("test test test test test test test test test test test junk")
            .build()
            .map_err(|e| eyre::eyre!("Failed to build signer: {}", e)).unwrap();

        signer.set_chain_id(Some(1337));

        let consensus = Consensus {
            committed_state: committed_state.clone(),
            current_state,
            signer,
        };
        let mempool = Mempool::default();
        let info = Info {
            state: committed_state,
        };
        let snapshot = Snapshot::default();

        App {
            consensus,
            mempool,
            info,
            snapshot,
        }
    }
}
