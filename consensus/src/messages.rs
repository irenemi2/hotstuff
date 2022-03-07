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

// pub type VoteType = u32;
// Vote1: 1, Vote2: 2,

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ProposedBlock{
    pub block:Block,
    pub qc:QC,
    pub tc:Option<TC>,
    pub ss:Option<SS>,
    pub author: PublicKey,
    pub signature: Signature,
}

impl ProposedBlock {
    pub async fn new(
        payload:Vec<Vec<u8>>,
        round:RoundNumber,
        qc: QC,
        tc: Option<TC>,
        ss: Option<SS>,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let proposedblock = Self {
            block:Block::genesis(),
            qc,
            tc,
            ss,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(proposedblock.digest()).await;

        let parent = match proposedblock.previous() {
            Ok(hash) => hash,
            Err(e) => { panic!("Block previous failed: {} (block content: {:?})", e, proposedblock); },
        };
        let block=Block::new(parent, author,round,payload, signature_service).await;
        Self {
            signature:signature,
            block:block,
            ..proposedblock
        }
    }

    pub fn genesis() -> Self {
        ProposedBlock::default()
    }

    pub fn previous(&self) -> ConsensusResult<Digest> { // TODO: return ProposedTuple instead?
        if self.tc.is_some() && self.ss.is_some() {
            return Err(ConsensusError::TCSSConflict);
        }
        //  else if let Some(ref tc) = self.tc {
        //     match tc.locked_digest() {
        //         Some(hash) => { return Ok(hash.clone()); },
        //         None => { return Err(ConsensusError::TCNoLock); },
        //     };
        // } else if let Some(ref ss) = self.ss {
        //     return Ok(ss.highest_digest().expect("Empty SS").clone());
        // }

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

        Ok(())
    }
}

impl Hash for ProposedBlock {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.qc.round.to_le_bytes());
        hasher.update(&self.previous().expect("Digest called before verify"));
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for ProposedBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: PB({},{})",
            self.digest(),
            self.author,
            self.qc.round
        )
    }
}

impl fmt::Display for ProposedBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "PB{}", self.block.round)
    }
}


#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Block {
    pub parent:Digest,
    pub author: PublicKey,
    pub round: RoundNumber,
    pub payload: Vec<Vec<u8>>,
    pub signature: Signature,
}

impl Block {
    pub async fn new(
        parent:Digest,
        author: PublicKey,
        round: RoundNumber,
        payload: Vec<Vec<u8>>,
        mut signature_service: SignatureService,
    ) -> Self {
        let block = Self {
            parent,
            author,
            round,
            payload,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(block.digest()).await;
        Self { signature, ..block }
    }

    pub fn genesis() -> Self {
        Block::default()
    }

    pub fn previous(&self) -> ConsensusResult<Digest> {
        // if self.qc.is_some() && self.tc.is_some() {
        //     return Err(ConsensusError::QCTCConflict);
        // } else if let Some(ref qc) = self.qc {
        //     return Ok(qc.hash.clone());
        // } else if let Some(ref tc) = self.tc {
        //     return Ok(tc.highest_digest().expect("Empty TC").clone());
        // }

        if bincode::serialize(self).expect("Failed to serialize block") == bincode::serialize(&Block::genesis()).expect("Failed to serialize block") {
            // Weird workaround for rust type inference to check if self block is the same as the genesis block
            // TODO: fix this
            return Ok(Digest::default());
        }
        // else{
        //     ()
        // }
        Err(ConsensusError::QCTCConflict)
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        let voting_rights = committee.stake(&self.author);
        ensure!(
            voting_rights > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check QC TC conflict
        // match self.previous() {
        //     Ok(_) => {},
        //     Err(e) => return Err(e),
        // };

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;

        // Check the embedded QC (if any).
        // if let Some(ref qc) = self.qc {
        //     if *qc != QC::genesis() {
        //         qc.verify(committee, 2)?;
        //     }
        // }

        // // Check the TC embedded in the block (if any).
        // if let Some(ref tc) = self.tc {
        //     tc.verify(committee)?;
        // }
        Ok(())
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.parent);
        hasher.update(self.author.0);
        hasher.update(self.round.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        // hasher.update(&self.previous().expect("Digest called before verify"));
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B({}, {},  {})",
            self.digest(),
            self.author,
            self.round,
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
    pub block: Block, // Inner Block 
    // pub round: RoundNumber,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Vote {
    pub async fn new(
        // vote_type: VoteType,
        block: Block,
        // round: RoundNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let vote = Self {
            // vote_type,
            block,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure correct VoteType
        // ensure!(
        //     self.vote_type == 1 || self.vote_type == 2,
        //     ConsensusError::UnknownVoteType(self.vote_type)
        // );

        // Ensure the authority has voting rights.
        // ensure!(
        //     committee.stake(&self.author) > 0,
        //     ConsensusError::UnknownAuthority(self.author)
        // );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        // hasher.update(self.vote_type.to_le_bytes());
        // hasher.update(self.hash.clone());
        // hasher.update(self.round.to_le_bytes());
        hasher.update(self.author.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "V({}, {})", self.author, self.block)
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
        write!(f, "QC(V{}, {})",  self.hash, self.round)
    }
}

impl PartialEq for QC {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.round == other.round
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Timeout {
    // pub high_qc: QC,
    // pub round: RoundNumber,
    pub block:Block,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Timeout {
    pub async fn new(
        block:Block,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let timeout = Self {
            block,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(timeout.digest()).await;
        Self {
            signature,
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

        // Check the embedded QC.
        // if self.high_qc != QC::genesis() {
        //     self.high_qc.verify(committee, 1)?;
        // }
        Ok(())
    }
}

impl Hash for Timeout {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        //block??
        hasher.update(self.author.0);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "T( {}, {:?})", self.author, self.signature)
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
                self.round == timeout.block.round,
                ConsensusError::MismatchTCTimeout(self.round, timeout.block.round)
            );

            timeout.verify(committee)?;
        }
        Ok(())
    }
    // check if needed
    pub fn high_qc_rounds(&self) -> Vec<RoundNumber> {
        self.votes.iter().map(|timeout| &timeout.block.round).cloned().collect() // CHECK: stealing ownership?
    }

    pub fn highest_tc_block(&self) -> Option<Block> {
        let highest_qc_round_vec = self.high_qc_rounds();
        let highest_qc_round = highest_qc_round_vec.iter().max().expect("Empty TC");

        for timeout in self.votes.iter() {
            if timeout.block.round == *highest_qc_round {
                return Some(timeout.block.clone());
            }
        }
        None
    }
}

impl fmt::Debug for TC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TC({}, {:?}, {:?})", self.round, self.high_qc_rounds(), self.highest_tc_block())
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
        
        // self.high_tc.verify(committee)?;
        Ok(())
    }
}

impl Hash for Status {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.round.to_le_bytes());
        hasher.update(self.high_qc.round.to_le_bytes());    
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "S({}, {}, {:?})", self.author, self.round, self.high_qc)
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
                ConsensusError::MismatchSSStatus(self.round, status.round)
            );

            status.verify(committee)?;
        }
        Ok(())
    }
    pub fn high_tc_rounds(&self) -> Vec<RoundNumber> {
        self.votes.iter().map(|status| &status.high_tc.round).cloned().collect() // CHECK: stealing ownership?
    }
    //check if needs to be highest tc?
    // pub fn highest_digest(&self) -> Option<&Digest> {
    //     let highest_tc_round_vec = self.high_tc_rounds();
    //     let highest_tc_round = highest_tc_round_vec.iter().max().expect("Empty TC");

    //     for status in self.votes.iter() {
    //         if status.high_tc.round == *highest_tc_round {
    //             return status.high_tc.locked_digest();
    //         }
    //     }
    //     None
    // }
    
    pub fn highest_status(&self) -> Option<Status>{
        let highest_tc_round_vec = self.high_tc_rounds();
        let highest_tc_round = highest_tc_round_vec.iter().max().expect("Empty TC");

        for status in self.votes.iter() {
            
            if status.high_tc.round == *highest_tc_round {
                return Some(status.clone());
            }
        }
        None
    }
}

impl fmt::Debug for SS {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "SS({})", self.round)
    }
}