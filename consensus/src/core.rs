use crate::aggregator::Aggregator;
use crate::config::{Committee, Parameters};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::mempool::{MempoolDriver, NodeMempool};
use crate::messages::{Block, Timeout, Vote1, Vote2, QC, TC};
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use async_recursion::async_recursion;
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{Digest, PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::NetMessage;
use serde::{Deserialize, Serialize};
use std::cmp::max;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration};
use std::collections::HashSet;

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub type RoundNumber = u64;
pub type Depth = u64;

#[derive(Serialize, Deserialize, Debug)]
pub enum CoreMessage {
    Propose(Block),
    Vote1(Vote1),
    Vote2(Vote2),
    Timeout(Timeout),
    LoopBack(Block),
    SyncRequest(Digest, PublicKey),
}

pub struct Core<Mempool> {
    name: PublicKey,
    committee: Committee,
    parameters: Parameters,
    store: Store,
    signature_service: SignatureService,
    leader_elector: LeaderElector,
    mempool_driver: MempoolDriver<Mempool>,
    synchronizer: Synchronizer,
    core_channel: Receiver<CoreMessage>,
    network_channel: Sender<NetMessage>,
    commit_channel: Sender<Block>,
    round: RoundNumber, // current round number
    last_voted_round: RoundNumber,
    vote1_qc: QC,
    vote2_qc: QC,
    timer: Timer<RoundNumber>,
    aggregator: Aggregator,
    commit_check: HashSet<Digest>, // for checking dup block commits, will eventually exhaust system mem
}

impl<Mempool: 'static + NodeMempool> Core<Mempool> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: PublicKey,
        committee: Committee,
        parameters: Parameters,
        signature_service: SignatureService,
        store: Store,
        leader_elector: LeaderElector,
        mempool_driver: MempoolDriver<Mempool>,
        synchronizer: Synchronizer,
        core_channel: Receiver<CoreMessage>,
        network_channel: Sender<NetMessage>,
        commit_channel: Sender<Block>,
    ) -> Self {
        let aggregator = Aggregator::new(committee.clone());
        Self {
            name,
            committee,
            parameters,
            signature_service,
            store,
            leader_elector,
            mempool_driver,
            synchronizer,
            network_channel,
            commit_channel,
            core_channel,
            round: 1,
            last_voted_round: 0,
            vote1_qc: QC::genesis(),
            vote2_qc: QC::genesis(),
            timer: Timer::new(),
            aggregator,
            commit_check: HashSet::new(),
        }
    }

    async fn store_block(&mut self, block: &Block) -> ConsensusResult<()> {
        let key = block.digest().to_vec();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store
            .write(key, value)
            .await
            .map_err(ConsensusError::from)
    }

    async fn schedule_timer(&mut self) {
        self.timer
            .schedule(self.parameters.timeout_delay, self.round)
            .await;
    }

    async fn transmit(
        &mut self,
        message: &CoreMessage,
        to: Option<PublicKey>,
    ) -> ConsensusResult<()> {
        let addresses = if let Some(to) = to {
            debug!("Sending {:?} to {}", message, to);
            vec![self.committee.address(&to)?]
        } else {
            debug!("Broadcasting {:?}", message);
            self.committee.broadcast_addresses(&self.name)
        };
        let bytes = bincode::serialize(message).expect("Failed to serialize core message");
        let message = NetMessage(Bytes::from(bytes), addresses);
        if let Err(e) = self.network_channel.send(message).await {
            panic!("Failed to send block through network channel: {}", e);
        }
        Ok(())
    }

    // -- Start Safety Module --
    fn increase_last_voted_round(&mut self, target: RoundNumber) {
        self.last_voted_round = max(self.last_voted_round, target);
    }

    async fn make_vote1(&mut self, block: &Block) -> Option<Vote1> {
        // Check if we can vote for this block/propose and make vote1

        // Condition1: node in same round as block
        let safety_rule_in_same_round = block.round == self.round;
        
        // Condition2: did not vote1 for this round before
        let safety_rule_no_equivocate_in_round = block.round > self.last_voted_round;

        // Condition3: block contains correct QC for parent/ancestor block
        // Note block already verified in handle proposal
        // or is verified already in generate proposal
        // Two cases:
        //      (1) have TC, then need block.qc.round + 1 == block.round
        //      (2) no TC,   then need block.qc.round + 1 <= block.round
        let mut safety_rule_right_parent_qc = block.qc.round + 1 == block.round;
        if let Some(ref tc) = block.tc {
            safety_rule_right_parent_qc = block.qc.round + 1 <= block.round;
        }

        // Condition4: if block contain TC, should be correct
        //             as in TC round is correct, timeout rounds should be correct
        //             and proposed value should follow TC timeouts
        // Note TC also verified when block is verified
        let mut safety_valid_tc = true;
        if let Some(ref tc) = block.tc {
            // tc match block round
            let mut tc_match_round = tc.round + 1 == block.round;
            tc_match_round &= block.qc.round + 1 <= *tc.high_qc_rounds().iter().max().expect("Empty TC");
            safety_valid_tc &= tc_match_round;

            // block repropose TC highest timeouts
            let reproposing_match_block = match tc.highest_timeout() {
                Some(timeout) => block.has_same_propose_val(&timeout.locked_block),
                None => false,
            };
            safety_valid_tc &= reproposing_match_block;
        }

        // Actual check
        if !(safety_rule_in_same_round &&
             safety_rule_no_equivocate_in_round &&
             safety_rule_right_parent_qc &&
             safety_valid_tc) {
            return None;
        }

        // Maintain condition2 to ensure we won't vote for contradicting blocks.
        self.increase_last_voted_round(block.round);

        // TODO [issue #15]: Write to storage preferred_round and last_voted_round.
        Some(Vote1::new(&block, self.name, self.signature_service.clone()).await)
    }

    // -- End Safety Module --

    // make_vote2 not in the safety module as it doesn't care
    async fn make_vote2(&mut self, vote: &Vote1) -> Vote2 {
        // Never checks, and always send vote2
        // Note that the vote quorum should already be checked
        Vote2::new(
            vote.hash.clone(),
            vote.round, self.name,
            self.signature_service.clone()).await
    }

    // -- Start Pacemaker --
    fn update_high_qc(&mut self, qc: &QC) {
        if qc.round > self.vote2_qc.round {
            self.vote2_qc = qc.clone();
        }
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        warn!("Timeout reached for round {}", self.round);
        self.increase_last_voted_round(self.round);
        let timeout = Timeout::new(
            self.high_qc.clone(),
            self.round,
            self.name,
            self.signature_service.clone(),
        )
        .await;
        debug!("Created {:?}", timeout);
        self.schedule_timer().await;
        let message = CoreMessage::Timeout(timeout.clone());
        self.transmit(&message, None).await?;
        self.handle_timeout(&timeout).await
    }

    #[async_recursion]
    async fn handle_vote1(&mut self, vote1: &Vote1) -> ConsensusResult<()> {
        debug!("Processing {:?}", vote1);
        // TODO: note > self.round votes are considered, need to check if fine
        if vote1.round < self.round {
            return Ok(());
        }

        // Ensure the vote1 is well formed.
        vote1.verify(&self.committee)?;

        // Add the new vote1 to our aggregator and see if we have a quorum.
        if let Some(qc) = self.aggregator.add_vote1(vote1.clone())? {
            debug!("Assembled {:?}", qc);

            // Store vote1 quorum and send all vote2
            self.vote1_qc = qc.clone();

            let vote2 = self.make_vote2(vote1).await;
            debug!("Created {:?}", vote2);

            let message = CoreMessage::Vote2(vote2);
            self.transmit(&message, None).await?;
            self.handle_vote2(&vote2).await?;
        }
        Ok(())
    }

    #[async_recursion]
    async fn handle_vote2(&mut self, vote2: &Vote2) -> ConsensusResult<()> {
        // This function performs the commit when seeing the quorum

        debug!("Processing {:?}", vote2);
        if vote2.round < self.round {
            return Ok(());
        }

        // Ensure the vote2 is well formed.
        vote2.verify(&self.committee)?;

        // Add the new vote2 to our aggregator and see if we have a quorum.
        if let Some(qc) = self.aggregator.add_vote2(vote2.clone())? {
            let saved_qc = qc.clone();
            debug!("Assembled {:?}", saved_qc);

            // Process the QC. This performs the view change
            self.process_vote2_qc(&saved_qc).await;

            // Make a new block/proposal if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(None).await?;
            }
        }
        Ok(())
    }

    async fn handle_timeout(&mut self, timeout: &Timeout) -> ConsensusResult<()> {
        debug!("Processing {:?}", timeout);
        if timeout.round < self.round {
            return Ok(());
        }

        // In pbft only leader needs to collect timeouts, optimization exists
        if self.name != self.leader_elector.get_leader(timeout.round+1) {
            return Ok(());
        }

        // Ensure the timeout is well formed.
        timeout.verify(&self.committee)?;

        // Process the QC embedded in the locked block of timeout.
        self.process_vote2_qc(&timeout.locked_block.qc).await;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(tc) = self.aggregator.add_timeout(timeout.clone())? {
            debug!("Assembled {:?}", tc);

            // Try to advance the round.
            self.advance_round(tc.round).await;

            // Update variable for block proposal

            // Make a new block as we are the next leader.
            self.generate_proposal(Some(tc)).await?;
        }
        Ok(())
    }

    #[async_recursion]
    async fn advance_round(&mut self, round: RoundNumber) {
        if round < self.round {
            return;
        }
        self.timer.cancel(self.round).await;
        self.round = round + 1;
        debug!("Moved to round {}", self.round);

        // Cleanup the vote aggregator.
        self.aggregator.cleanup(&self.round);

        // Schedule a new timer for this round.
        self.schedule_timer().await;
    }
    // -- End Pacemaker --

    #[async_recursion]
    async fn generate_proposal(&mut self, tc: Option<TC>) -> ConsensusResult<()> {
        // Make a new block.
        let payload = self
            .mempool_driver
            .get(self.parameters.max_payload_size)
            .await;
        let block = Block::new(
            self.vote2_qc.clone(),
            tc,
            self.name,
            self.round,
            payload,
            self.signature_service.clone(),
        )
        .await;
        if !block.payload.is_empty() {
            info!("Created {}", block);

            #[cfg(feature = "benchmark")]
            for x in &block.payload {
                info!("Created B{}({})", block.round, base64::encode(x));
            }
        }
        debug!("Created {:?}", block);

        // Process our new block and broadcast it.
        let message = CoreMessage::Propose(block.clone());
        self.transmit(&message, None).await?;
        self.process_block(&block).await?;

        // Wait for the minimum block delay.
        sleep(Duration::from_millis(self.parameters.min_block_delay)).await;
        Ok(())
    }

    async fn process_vote2_qc(&mut self, qc: &QC) {
        self.advance_round(qc.round).await;
        self.update_high_qc(qc);
    }

    #[async_recursion]
    async fn process_block(&mut self, block: &Block) -> ConsensusResult<()> {
        debug!("Processing {:?}", block);

        // Let's see if we have the parent of the block, that is:
        //          |...;parent| <- |parent QC; block|
        // If we don't, the synchronizer asks for it from other nodes. It will
        // then ensure we process the ancestors in the correct order, and
        // finally make us resume processing this block.
        let parent = match self.synchronizer.get_ancestor(block).await? {
            Some(ancestor) => ancestor,
            None => {
                debug!("Processing of {} suspended: missing parent", block.digest());
                return Ok(());
            }
        };

        // Store the block only if we have already processed all the ancestors.
        self.store_block(block).await?;

        // Cleanup the mempool.
        self.mempool_driver.cleanup(&parent).await;

        // Commit the parent block.
        // We must already have a valid vote2 quorum for this.
        // Note it is possible that we have already committed the parent block.
        // This is checked in the commit function
        self.commit_block(&parent).await;

        // Ensure the block's round is as expected.
        // This check is important: it prevents bad leaders from producing blocks
        // far in the future that may cause overflow on the round number.
        // TODO: think about if in pbft nodes may not reach the proposal round
        //       before the leader sendes out the block for new round
        if block.round != self.round {
            return Ok(());
        }

        // See if we can vote for this block.
        if let Some(vote1) = self.make_vote1(block).await {
            debug!("Created {:?}", vote1);
            let next_leader = self.leader_elector.get_leader(self.round + 1);
            if next_leader == self.name {
                self.handle_vote1(&vote1).await?;
            } else {
                let message = CoreMessage::Vote1(vote1);
                self.transmit(&message, Some(next_leader)).await?;
            }
        }
        Ok(())
    }

    async fn commit_block(&mut self, block: &Block) {
        // Check if we can commit the block
        // Note it is assumed that the vote2 quorum commit rule is already satisfied
        if self.commit_check.contains(&block.digest()) {
            return;
        }

        if !block.payload.is_empty() {
            info!("Committed {}", block);

            #[cfg(feature = "benchmark")]
            for x in &block.payload {
                info!("Committed B{}({})", block.round, base64::encode(x));
            }
        }
        debug!("Committed {:?}", block);
        self.commit_check.insert(block.digest().clone());
        if let Err(e) = self.commit_channel.send(block.clone()).await {
            warn!("Failed to send block through the commit channel: {}", e);
        }
    }

    async fn handle_proposal(&mut self, block: &Block) -> ConsensusResult<()> {
        let digest = block.digest();

        // Ensure the block proposer is the right leader for the round.
        ensure!(
            block.author == self.leader_elector.get_leader(block.round),
            ConsensusError::WrongLeader {
                digest,
                leader: block.author,
                round: block.round
            }
        );

        // Check the block is correctly formed.
        block.verify(&self.committee)?;

        // Process the QC. This may allow us to advance round.
        self.process_vote2_qc(&block.qc).await;

        // Process the TC (if any). This may also allow us to advance round.
        if let Some(ref tc) = block.tc {
            self.advance_round(tc.round).await;
        }

        // Let's see if we have the block's data. If we don't, the mempool
        // will get it and then make us resume processing this block.
        if !self.mempool_driver.verify(block).await? {
            debug!("Processing of {} suspended: missing payload", digest);
            return Ok(());
        }

        // All check pass, we can process this block.
        self.process_block(block).await
    }

    async fn handle_sync_request(
        &mut self,
        digest: Digest,
        sender: PublicKey,
    ) -> ConsensusResult<()> {
        if let Some(bytes) = self.store.read(digest.to_vec()).await? {
            let block = bincode::deserialize(&bytes)?;
            let message = CoreMessage::Propose(block);
            self.transmit(&message, Some(sender)).await?;
        }
        Ok(())
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
        // Also, schedule a timer in case we don't hear from the leader.
        self.schedule_timer().await;
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(None)
                .await
                .expect("Failed to send the first block");
        }

        // This is the main loop: it processes incoming blocks and votes,
        // and receive timeout notifications from our Timeout Manager.
        loop {
            let result = tokio::select! {
                Some(message) = self.core_channel.recv() => {
                    match message {
                        CoreMessage::Propose(block) => self.handle_proposal(&block).await,
                        CoreMessage::Vote1(vote) => self.handle_vote1(&vote).await,
                        CoreMessage::Vote2(vote) => self.handle_vote2(&vote).await,
                        CoreMessage::Timeout(timeout) => self.handle_timeout(&timeout).await,
                        CoreMessage::LoopBack(block) => self.process_block(&block).await,
                        CoreMessage::SyncRequest(digest, sender) => self.handle_sync_request(digest, sender).await
                    }
                },
                Some(_) = self.timer.notifier.recv() => self.local_timeout_round().await,
                else => break,
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}
