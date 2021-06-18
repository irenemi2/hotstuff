use crate::config::Committee;
use crate::core::CoreMessage;
use crate::error::ConsensusResult;
use crate::messages::{Block, QC};
use crate::timer::Timer;
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{Digest, PublicKey};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use log::{debug, error};
use network::NetMessage;
use std::collections::HashSet;
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};

#[cfg(test)]
#[path = "tests/synchronizer_tests.rs"]
pub mod synchronizer_tests;

pub struct Synchronizer {
    store: Store,
    inner_channel: Sender<(Digest, Block)>,
}

impl Synchronizer {
    pub async fn new(
        name: PublicKey,
        committee: Committee,
        store: Store,
        network_channel: Sender<NetMessage>,
        core_channel: Sender<CoreMessage>,
        sync_retry_delay: u64,
    ) -> Self {
        let (tx_inner, mut rx_inner): (_, Receiver<(Digest, Block)>) = channel(1000);
        let mut timer = Timer::new();
        timer.schedule(sync_retry_delay, true).await;

        let store_copy = store.clone();
        tokio::spawn(async move {
            let mut waiting = FuturesUnordered::new();
            let mut pending = HashSet::new();
            let mut requests = HashSet::new();
            loop {
                tokio::select! {
                    Some((target_digest, replay_block)) = rx_inner.recv() => {
                        if pending.insert(replay_block.digest()) {
                            let fut = Self::waiter(store_copy.clone(), target_digest.clone(), replay_block);
                            waiting.push(fut);
                            if requests.insert(target_digest.clone()) {
                                Self::transmit(target_digest, &name, &committee, &network_channel).await;
                            }
                        }
                    },
                    Some(result) = waiting.next() => {
                        match result {
                            Ok((target_digest, replay_block)) => {
                                let _ = pending.remove(&replay_block.digest());
                                let _ = requests.remove(&target_digest);
                                let message = CoreMessage::LoopBack(replay_block);
                                if let Err(e) = core_channel.send(message).await {
                                    panic!("Failed to send message through core channel: {}", e);
                                }
                            },
                            Err(e) => error!("{}", e)
                        }
                    },
                    Some(_) = timer.notifier.recv() => {
                        // This implements the 'perfect point to point link' abstraction.
                        for digest in &requests {
                            Self::transmit(digest.clone(), &name, &committee, &network_channel).await;
                        }
                        timer
                            .schedule(sync_retry_delay, true)
                            .await;
                    },
                    else => break,
                }
            }
        });
        Self {
            store,
            inner_channel: tx_inner,
        }
    }

    async fn waiter(mut store: Store, wait_on: Digest, deliver: Block) -> ConsensusResult<(Digest, Block)> {
        let _ = store.notify_read(wait_on.to_vec()).await?;
        Ok((wait_on, deliver))
    }

    async fn transmit(
        digest: Digest,
        name: &PublicKey,
        committee: &Committee,
        network_channel: &Sender<NetMessage>,
    ) {
        debug!("Requesting sync for block {}", digest);
        let addresses = committee.broadcast_addresses(&name);
        let message = CoreMessage::SyncRequest(digest, *name);
        let bytes = bincode::serialize(&message).expect("Failed to serialize core message");
        let message = NetMessage(Bytes::from(bytes), addresses);
        if let Err(e) = network_channel.send(message).await {
            panic!("Failed to send block through network channel: {}", e);
        }
    }

    async fn get_previous_block(
        &mut self,
        child_block: &Block,
        replay_block: &Block,
    ) -> ConsensusResult<Option<Block>> {
        let previous = child_block.previous().expect("Verified block does not have parent"); // should never panic for verified block

        if *previous == QC::genesis().hash { // QC::genesis().hash should be consistent to work
            return Ok(Some(Block::genesis()));
        }

        match self.store.read(previous.to_vec()).await? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => {
                if let Err(e) = self.inner_channel.send((previous.clone(), replay_block.clone())).await {
                    panic!("Failed to send request to synchronizer: {}", e);
                }
                Ok(None)
            }
        }
    }

    pub async fn get_parent(
        &mut self,
        child_block: &Block,
        replay_block: &Block,
    ) -> ConsensusResult<Option<Block>> {
        let parent = match self.get_previous_block(child_block, replay_block).await? {
            Some(b) => b,
            None => return Ok(None),
        };
        Ok(Some(parent))
    }

    pub async fn get_block(
        &mut self,
        hash: &Digest,
    ) -> ConsensusResult<Option<Block>> {
        if *hash == Block::genesis().digest() {
            return Ok(Some(Block::genesis()));
        }

        match self.store.read(hash.to_vec()).await? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => Ok(None),
        }
    }
}
