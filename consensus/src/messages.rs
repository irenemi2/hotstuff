use crate::config::Committee;
use crate::core::RoundNumber;
use crate::error::{ConsensusError, ConsensusResult};
use crypto::{Digest, Hash, PublicKey, Signature, SignatureService};
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::convert::TryInto;
use std::fmt;

#[cfg(test)]
#[path = "tests/messages_tests.rs"]
pub mod messages_tests;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ProposedTuple {
    pub parent: Digest,
    pub block: Digest,
    pub round: RoundNumber,
    pub author: PublicKey,
    pub signature: Signature,
}

impl ProposedTuple {
    pub async fn new(
        parent: Digest,
        block: Digest,
        round: RoundNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let pt = Self {
            parent,
            block,
            round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(pt.digest()).await;
        Self { signature, ..pt }
    }

    pub fn genesis() -> Self {
        ProposedTuple::default()
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        Ok(())
    }
}

impl Hash for ProposedTuple {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.parent);
        hasher.update(&self.block);
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for ProposedTuple {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: PT({}, {}, {})",
            self.digest(),
            self.parent,
            self.block,
            self.round,
        )
    }
}

impl fmt::Display for ProposedTuple {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "PT{}", self.round)
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub qc: QC,
    pub tc: Option<TC>,
    pub ss: Option<SS>,
    pub round: RoundNumber, // height not needed as in org paper design due to round-robin leader
    pub payload: Vec<Vec<u8>>,
    pub author: PublicKey,
    pub ptsignature: Signature,
    pub signature: Signature,
}

impl Block {
    pub async fn new(
        qc: QC,
        tc: Option<TC>,
        ss: Option<SS>,
        round: RoundNumber,
        payload: Vec<Vec<u8>>,
        author: PublicKey,
        ptsignature: SignatureService,
        mut signature_service: SignatureService,
    ) -> Self {
        let block = Self {
            qc,
            tc,
            ss,
            round,
            payload,
            author,
            ptsignature: Signature::default(),
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(block.digest()).await;

        let parent = match block.previous() {
            Ok(hash) => hash,
            Err(e) => { panic!("Block previous failed: {} (block content: {:?})", e, block); },
        };
        let pt = ProposedTuple::new(parent, block.digest(), round, author, signature_service).await;

        Self {
            ptsignature: pt.signature,
            signature: signature,
            ..block
        }
    }

    pub fn genesis() -> Self {
        Block::default()
    }

    pub fn previous(&self) -> ConsensusResult<Digest> { // TODO: return ProposedTuple instead?
        if self.tc.is_some() && self.ss.is_some() {
            return Err(ConsensusError::TCSSConflict);
        } else if let Some(ref tc) = self.tc {
            match tc.locked_digest() {
                Some(hash) => { return Ok(hash.clone()); },
                None => { return Err(ConsensusError::TCNoLock); },
            };
        } else if let Some(ref ss) = self.ss {
            return Ok(ss.highest_digest().expect("Empty SS").clone());
        }

        if bincode::serialize(self).expect("Failed to serialize block") == bincode::serialize(&Block::genesis()).expect("Failed to serialize block") {
            // Weird workaround for rust type inference to check if self block is the same as the genesis block
            // TODO: check genesis condition
            return Ok(Digest::default());
        }

        Ok(self.qc.hash.clone())
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> { // TODO: check more??
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check TC SS conflict
        let parent = match self.previous() {
            Ok(hash) => hash,
            Err(e) => { return Err(e) },
        };

        // Check the block signature.
        self.signature.verify(&self.digest(), &self.author)?;

        // Check the embedded QC
        if self.qc != QC::genesis() {
            self.qc.verify(committee)?; // TODO: also verify qc is locking immediate ancestor when tc/ss present?
        }

        // Check the TC embedded in the block (if any).
        if let Some(ref tc) = self.tc {
            tc.verify(committee)?;
        }

        // Check the SS embedded in the block (if any).
        if let Some(ref ss) = self.ss {
            ss.verify(committee)?;
        }

        // Check the ptsignature.
            // let pt = ProposedTuple {
            //     parent: parent,
            //     block: self.digest(),
            //     self.round,
            //     self.author,
            //     self.signature,
            // };
        self.ptsignature.verify(&self.digest(), &self.author)?;

        Ok(())
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.round.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        hasher.update(&self.previous().expect("Digest called before verify"));
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B({}, {}, {:?}, {:?},{:?} {})",
            self.digest(),
            self.author,
            self.round,
            self.qc,
            self.tc,
            self.ss,
            self.payload.iter().map(|x| x.len()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}", self.round)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    // pub vote_type: VoteType,
    pub hash: Digest, // Block hash
    pub round: RoundNumber,
    pub author: PublicKey,
    pub ptsignature: Signature,
    pub signature: Signature,
}

impl Vote {
    pub async fn new(
        // vote_type: VoteType,
        block: &Block,
        author: PublicKey,
        //
        mut signature_service: SignatureService,
    ) -> Self {
        let vote = Self {
            // vote_type,
            hash: block.digest(),
            round: block.round,
            author,
            ptsignature:Signature::default(),
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        let parent = match block.previous() {
            Ok(hash) => hash,
            Err(e) => { panic!("Block previous failed: {} (block content: {:?})", e, block); },
        };
        let pt = ProposedTuple::new(parent, block.digest(), block.round, author, signature_service).await;

        Self { 
            ptsignature: pt.signature,
            signature: signature,
            ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure correct VoteType
        // ensure!(
        //     self.vote_type == 1 || self.vote_type == 2,
        //     ConsensusError::UnknownVoteType(self.vote_type)
        // );

        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;
        
        //check ptsignature?
        self.ptsignature.verify(&self.digest(), &self.author)?;
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        // hasher.update(self.vote_type.to_le_bytes());
        hasher.update(self.hash.clone());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "V{}({}, {})", self.author, self.round, self.hash)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct QC {
    // pub vote_type: VoteType,
    pub hash: Digest,
    pub round: RoundNumber,
    pub votes: Vec<(PublicKey, Signature)>,
}

impl QC {
    pub fn genesis() -> Self {
        QC::default()
    }

    pub fn timeout(&self) -> bool {
        self.hash == Digest::default() && self.round != 0
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure QC type matched expectation
        // ensure!(
        //     self.vote_type == expected_vote_type,
        //     ConsensusError::InvalidVoteType(self.vote_type, expected_vote_type)
        // );

        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _) in self.votes.iter() {
            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::QCRequiresQuorum
        );
        //check pt signature?
        // Check the signatures.
        Signature::verify_batch(&self.digest(), &self.votes).map_err(ConsensusError::from)
    }
}

impl Hash for QC {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        // hasher.update(self.vote_type.to_le_bytes());
        hasher.update(self.hash.clone());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "QC(V{}, {})", self.hash, self.round)
    }
}

impl PartialEq for QC {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.round == other.round
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    pub high_qc: QC,
    pub round: RoundNumber,
    pub author: PublicKey,
    pub ptsignature:Signature,
    pub signature: Signature,
}

impl Timeout {
    pub async fn new(
        block:&Block,
        high_qc: QC,
        round: RoundNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let timeout = Self {
            high_qc,
            round,
            author,
            ptsignature:Signature::default(),
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(timeout.digest()).await;
        let parent = match block.previous() {
            Ok(hash) => hash,
            Err(e) => { panic!("Block previous failed: {} (block content: {:?})", e, block); },
        };
        let pt = ProposedTuple::new(parent, block.digest(), round, author, signature_service).await;

        Self {
            ptsignature: pt.signature,
            signature: signature,
            ..timeout
        }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;
        self.ptsignature.verify(&self.digest(), &self.author)?;
        // Check the embedded QC.
        if self.high_qc != QC::genesis() {
            self.high_qc.verify(committee)?;
        }
        Ok(())
    }
}

impl Hash for Timeout {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.high_qc.round.to_le_bytes()); // ???: Need vote_type?
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "T({}, {}, {:?})", self.author, self.round, self.high_qc)
    }
}

#[derive(Clone, Serialize, Deserialize,Default)]
pub struct TC {
    pub round: RoundNumber,
    pub votes: Vec<Timeout>,
}

impl TC {
    pub fn genesis() -> Self {
        TC::default()
    }
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the TC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for timeout in self.votes.iter() {
            let name = &timeout.author;

            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::TCRequiresQuorum
        );

        // Check the signatures.
        for timeout in &self.votes {
            ensure!(
                self.round == timeout.round,
                ConsensusError::MismatchTCTimeout(self.round, timeout.round)
            );

            timeout.verify(committee)?;
        }
        Ok(())
    }

    pub fn high_qc_rounds(&self) -> Vec<RoundNumber> {
        self.votes.iter().map(|timeout| &timeout.high_qc.round).cloned().collect() // CHECK: stealing ownership?
    }
    //locked digest?
    pub fn locked_digest(&self) -> Option<&Digest> {
        let highest_qc_round_vec = self.high_qc_rounds();
        let highest_qc_round = highest_qc_round_vec.iter().max().expect("Empty TC");

        for timeout in self.votes.iter() {
            if timeout.high_qc.round == *highest_qc_round {
                return Some(&timeout.high_qc.hash);
            }
        }
        None
    }
    pub fn highest_digest(&self) -> Option<&Digest> {
        let highest_qc_round_vec = self.high_qc_rounds();
        let highest_qc_round = highest_qc_round_vec.iter().max().expect("Empty TC");

        for timeout in self.votes.iter() {
            if timeout.high_qc.round == *highest_qc_round {
                return Some(&timeout.high_qc.hash);
            }
        }
        None
    }
}

impl fmt::Debug for TC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TC({}, {:?}, {:?})", self.round, self.high_qc_rounds(), self.highest_digest())
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Status{
    pub high_qc: QC,
    pub high_tc:TC,
    pub round: RoundNumber,
    pub author: PublicKey,
    pub signature: Signature,
}
impl Status {
    pub async fn new(
        high_qc: QC,
        high_tc:TC,
        round: RoundNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let status = Self {
            high_qc,
            high_tc,
            round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(status.digest()).await;
        Self {
            signature,
            ..status
        }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        // Check the embedded QC.
        if self.high_qc != QC::genesis() {
            self.high_qc.verify(committee)?;
        }
        
        self.high_tc.verify(committee)?;
        
        Ok(())
    }
}

impl Hash for Status {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.high_qc.round.to_le_bytes()); // ???: Need vote_type?
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "T({}, {}, {:?})", self.author, self.round, self.high_qc)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SS{
    pub round: RoundNumber,
    pub votes: Vec<Status>,
}
impl SS {
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the SS has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for status in self.votes.iter() {
            let name = &status.author;

            ensure!(!used.contains(name), ConsensusError::AuthorityReuse(*name));
            let voting_rights = committee.stake(name);
            ensure!(voting_rights > 0, ConsensusError::UnknownAuthority(*name));
            used.insert(*name);
            weight += voting_rights;
        }
        ensure!(
            weight >= committee.quorum_threshold(),
            ConsensusError::TCRequiresQuorum
        );

        // Check the signatures.
        for status in &self.votes {
            ensure!(
                self.round == status.round,
                ConsensusError::MismatchTCTimeout(self.round, status.round)
            );

            status.verify(committee)?;
        }
        Ok(())
    }

    pub fn high_qc_rounds(&self) -> Vec<RoundNumber> {
        self.votes.iter().map(|status| &status.high_qc.round).cloned().collect() // CHECK: stealing ownership?
    }
    //check if needs to be highest tc?
    pub fn highest_digest(&self) -> Option<&Digest> {
        let highest_qc_round_vec = self.high_qc_rounds();
        let highest_qc_round = highest_qc_round_vec.iter().max().expect("Empty TC");

        for status in self.votes.iter() {
            if status.high_qc.round == *highest_qc_round {
                return Some(&status.high_qc.hash);
            }
        }
        None
    }
}

impl fmt::Debug for SS {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "SS({}, {:?}, {:?})", self.round, self.high_qc_rounds(), self.highest_digest())
    }
}