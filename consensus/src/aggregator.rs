use crate::config::{Committee, Stake};
use crate::core::RoundNumber;
use crate::error::{ConsensusError, ConsensusResult};
use crate::messages::{Timeout, Vote1, Vote2, QC, TC};
use crypto::Hash as _;
use crypto::{Digest, PublicKey, Signature};
use std::collections::{HashMap, HashSet};

#[cfg(test)]
#[path = "tests/aggregator_tests.rs"]
pub mod aggregator_tests;

pub struct Aggregator {
    committee: Committee,
    vote1_aggregators: HashMap<RoundNumber, HashMap<Digest, Box<QCMaker>>>,
    vote2_aggregators: HashMap<RoundNumber, HashMap<Digest, Box<QCMaker>>>,
    timeouts_aggregators: HashMap<RoundNumber, Box<TCMaker>>,
}

impl Aggregator {
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            vote1_aggregators: HashMap::new(),
            vote2_aggregators: HashMap::new(),
            timeouts_aggregators: HashMap::new(),
        }
    }

    pub fn add_vote1(&mut self, vote1: Vote1) -> ConsensusResult<Option<QC>> {
        // TODO: A bad node may make us run out of memory by sending many votes
        // with different round numbers or different digests.

        // Add the new vote to our aggregator and see if we have a QC.
        self.vote1_aggregators
            .entry(vote1.round)
            .or_insert_with(HashMap::new)
            .entry(vote1.digest())
            .or_insert_with(|| Box::new(QCMaker::new()))
            .append1(vote1, &self.committee)
    }

    pub fn add_vote2(&mut self, vote2: Vote2) -> ConsensusResult<Option<QC>> {
        // TODO: A bad node may make us run out of memory by sending many votes
        // with different round numbers or different digests.

        // Add the new vote to our aggregator and see if we have a QC.
        self.vote2_aggregators
            .entry(vote2.round)
            .or_insert_with(HashMap::new)
            .entry(vote2.digest())
            .or_insert_with(|| Box::new(QCMaker::new()))
            .append2(vote2, &self.committee)
    }

    pub fn add_timeout(&mut self, timeout: Timeout) -> ConsensusResult<Option<TC>> {
        // TODO: A bad node may make us run out of memory by sending many timeouts
        // with different round numbers.

        // Add the new timeout to our aggregator and see if we have a TC.
        self.timeouts_aggregators
            .entry(timeout.round)
            .or_insert_with(|| Box::new(TCMaker::new()))
            .append(timeout, &self.committee)
    }

    pub fn cleanup(&mut self, round: &RoundNumber) {
        self.vote1_aggregators.retain(|k, _| k >= round);
        self.vote2_aggregators.retain(|k, _| k >= round);
        self.timeouts_aggregators.retain(|k, _| k >= round);
    }
}

struct QCMaker {
    weight: Stake,
    votes: Vec<(PublicKey, Signature)>,
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

    /// Try to append a signature to a (partial) quorum, for Vote1
    pub fn append1(&mut self, vote: Vote1, committee: &Committee) -> ConsensusResult<Option<QC>> {
        let author = vote.author;

        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuse(author)
        );

        self.votes.push((author, vote.signature));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures QC is only made once.
            return Ok(Some(QC {
                hash: vote.hash.clone(),
                round: vote.round,
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }

    /// Try to append a signature to a (partial) quorum, for Vote2
    pub fn append2(&mut self, vote: Vote2, committee: &Committee) -> ConsensusResult<Option<QC>> {
        let author = vote.author;

        // Ensure it is the first time this authority votes.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuse(author)
        );

        self.votes.push((author, vote.signature));
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures QC is only made once.
            return Ok(Some(QC {
                hash: vote.hash.clone(),
                round: vote.round,
                votes: self.votes.clone(),
            }));
        }
        Ok(None)
    }
}

struct TCMaker {
    weight: Stake,
    timeouts: Vec<Timeout>,
    used: HashSet<PublicKey>,
}

impl TCMaker {
    pub fn new() -> Self {
        Self {
            weight: 0,
            timeouts: Vec::new(),
            used: HashSet::new(),
        }
    }

    /// Try to append a signature to a (partial) quorum.
    pub fn append(
        &mut self,
        timeout: Timeout,
        committee: &Committee,
    ) -> ConsensusResult<Option<TC>> {
        let org_timeout = timeout.clone();
        let author = timeout.author;

        // Ensure it is the first time this authority timeouts.
        ensure!(
            self.used.insert(author),
            ConsensusError::AuthorityReuse(author)
        );

        // Add the timeout to the accumulator.
        self.timeouts
            .push(org_timeout);
        self.weight += committee.stake(&author);
        if self.weight >= committee.quorum_threshold() {
            self.weight = 0; // Ensures TC is only created once.
            return Ok(Some(TC {
                round: timeout.round,
                timeouts: self.timeouts.clone(),
            }));
        }
        Ok(None)
    }
}
