use crate::config::{Committee, Stake};
use crate::core::RoundNumber;
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::{Timeout, Vote, QC, TC,Status,SS};
use crypto::Hash as _;
use log::{debug};
use crypto::{Digest, PublicKey, Signature};
use std::collections::{HashMap, HashSet};

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

pub struct Aggregator {
    committee: Committee,
    votes_aggregators: HashMap<RoundNumber, HashMap<Digest, Box<QCMaker>>>,
    // vote2_aggregators: HashMap<RoundNumber, HashMap<Digest, Box<QCMaker>>>,
    timeouts_aggregators: HashMap<RoundNumber, Box<TCMaker>>,
    status_aggregators: HashMap<RoundNumber, Box<SSMaker>>,
}

impl Aggregator {
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            votes_aggregators: HashMap::new(),
            // vote2_aggregators: HashMap::new(),
            timeouts_aggregators: HashMap::new(),//status aggregators
            status_aggregators: HashMap::new(),
        }
    }

    // pub fn add_vote1(&mut self, vote: Vote) -> ConsensusResult<Option<QC>> {
    //     // TODO: A bad node may make us run out of memory by sending many votes
    //     // with different round numbers or different digests.

    //     // assert!(vote.vote_type == 1);

    //     // Add the new vote to our aggregator and see if we have a QC.
    //     self.vote1_aggregators
    //         .entry(vote.round)
    //         .or_insert_with(HashMap::new)
    //         .entry(vote.digest())
    //         .or_insert_with(|| Box::new(QCMaker::new()))
    //         .append(vote, &self.committee)
    // }

    // pub fn add_vote2(&mut self, vote: Vote) -> ConsensusResult<Option<QC>> {
    //     // TODO: A bad node may make us run out of memory by sending many votes
    //     // with different round numbers or different digests.

    //     // assert!(vote.vote_type == 2);

    //     // Add the new vote to our aggregator and see if we have a QC.
    //     self.vote2_aggregators
    //         .entry(vote.round)
    //         .or_insert_with(HashMap::new)
    //         .entry(vote.digest())
    //         .or_insert_with(|| Box::new(QCMaker::new()))
    //         .append(vote, &self.committee)
    // }
    pub fn add_vote(&mut self, vote: Vote) -> ConsensusResult<Option<QC>> {
        // TODO [issue #7]: A bad node may make us run out of memory by sending many votes
        // with different round numbers or different digests.
        debug!("Adding vote to aggregator {}", vote);
        // Add the new vote to our aggregator and see if we have a QC.
        self.votes_aggregators
            .entry(vote.block.round)
            .or_insert_with(HashMap::new)
            .entry(vote.digest())
            .or_insert_with(|| Box::new(QCMaker::new()))
            .append(vote, &self.committee)
    }
    pub fn add_timeout(&mut self, timeout: Timeout) -> ConsensusResult<Option<TC>> {
        // TODO: A bad node may make us run out of memory by sending many timeouts
        // with different round numbers.

        // Add the new timeout to our aggregator and see if we have a TC.
        self.timeouts_aggregators
            .entry(timeout.block.round)
            .or_insert_with(|| Box::new(TCMaker::new()))
            .append(timeout, &self.committee)
    }
    pub fn add_status(&mut self, status: Status) -> ConsensusResult<Option<SS>> {
        // TODO: A bad node may make us run out of memory by sending many timeouts
        // with different round numbers.

        // Add the new timeout to our aggregator and see if we have an SS.
        self.status_aggregators
            .entry(status.round)
            .or_insert_with(|| Box::new(SSMaker::new()))
            .append(status, &self.committee)
    }

    pub fn cleanup(&mut self, round: &RoundNumber) {
        // self.vote1_aggregators.retain(|k, _| k >= round);
        self.votes_aggregators.retain(|k, _| k >= round);
        self.timeouts_aggregators.retain(|k, _| k >= round);
        self.status_aggregators.retain(|k, _| k >= round);
    }
}

struct QCMaker {
    weight: Stake,
    votes: Vec<Vote>,
    used: HashSet<PublicKey>,
}

impl QCMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(&mut self, vote: Vote, committee: &Committee) -> ConsensusResult<Option<QC>> {
        let author = vote.author;

        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuse(author)
        );
        debug!("In append {}", vote);
        self.votes.push(vote.clone());
        debug!("Pushed vote {}", vote);
        self.weight += committee.stake(&author);
        debug!("Committee stake {},{}", &author,committee.stake(&author));
        debug!("Weight Threshold {}, {}", self.weight,committee.quorum_threshold());
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures QC is only made once.
            debug!("Trying to return QC {}", vote);
            return Ok(Some(QC {
                // vote_type: vote.vote_type,
                // hash: vote.block.digest(),
                round: vote.block.round,
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}

struct TCMaker {
    weight: Stake,
    votes: Vec<Timeout>,
    used: HashSet<PublicKey>,
}

impl TCMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        timeout: Timeout,
        committee: &Committee,
    ) -> ConsensusResult<Option<TC>> {
        let author = timeout.author;

        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuse(author)
        );

        // Add the timeout to the accumulator.
        self.votes.push(timeout.clone());
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures TC is only created once.
            return Ok(Some(TC {
                round: timeout.block.round,
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}
// SSMaker structure of SS
struct SSMaker {
    weight: Stake,
    votes: Vec<Status>,
    used: HashSet<PublicKey>,
}

impl SSMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            votes: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        status: Status,
        committee: &Committee,
    ) -> ConsensusResult<Option<SS>> {
        let author = status.author;

        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuse(author)
        );

        // Add the timeout to the accumulator.
        self.votes.push(status.clone());
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures TC is only created once.
            return Ok(Some(SS {
                round: status.round,
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}