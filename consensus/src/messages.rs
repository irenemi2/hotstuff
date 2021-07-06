use crate::config::Committee;
use crate::core::{RoundNumber, Height};
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
pub struct Block {
    pub parent: Digest,
    pub height: Height,
    pub txn: Vec<Vec<u8>>,
}

impl Block {
    pub async fn new(
        parent: Digest,
        height: Height,
        txn: Vec<Vec<u8>>,
    ) -> Self {
        Self { parent, height, txn }
    }

    pub fn genesis() -> Self {
        Block::default()
    }
}

impl Hash for Block {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.parent);
        hasher.update(self.height.to_le_bytes());
        for x in &self.txn {
            hasher.update(x);
        }
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B({}, {}, {:?})",
            self.digest(),
            self.parent,
            self.height,
            self.txn.iter().map(|x| x.len()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}", self.height)
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct ProposedTuple {
    pub block: Block,
    pub round: RoundNumber,
    pub author: PublicKey,
    pub signature: Signature,
}

impl ProposedTuple {
    pub async fn new(
        block: Block,
        round: RoundNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let pt = Self {
            block,
            round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(pt.digest()).await;
        Self { signature, ..pt }
    }

    pub fn previous(&self) -> &Digest {
        &self.block.parent
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
        hasher.update(&self.block.digest());
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for ProposedTuple {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: PT({:?}, {}, {})",
            self.digest(),
            self.block,
            self.round,
            self.author,
        )
    }
}

impl fmt::Display for ProposedTuple {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "PT{}", self.round)
    }
}

impl PartialEq for ProposedTuple {
    fn eq(&self, other: &Self) -> bool {
        self.block == other.block &&
        self.round == other.round &&
        self.author == other.author // assuming pt already verified, so no need to check sig
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Propose {
    pub pt: ProposedTuple,
    pub qc: QC,
    pub tc: Option<TC>,
    pub ss: Option<StatusSet>, // ss stands for StatuSet, not secret service
    pub author: PublicKey,
    pub signature: Signature,
}

impl Propose {
    pub async fn new(
        pt: ProposedTuple,
        qc: QC,
        tc: Option<TC>,
        ss: Option<StatusSet>,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let propose = Self {
            pt,
            qc,
            tc,
            ss,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(propose.digest()).await;
        Self { signature, ..propose }
    }

    pub fn genesis() -> Self {
        Propose::default() // TODO: check if conflict Block genesis
    }

    pub fn previous(&self) -> &Digest {
        &self.qc.hash
    }

    pub fn get_locked_block(&self) -> ConsensusResult<Option<&Block>> {
        if self.tc.is_some() && self.ss.is_some() {
            return Err(ConsensusError::TCSSConflict);
        } else if let Some(ref tc) = self.tc {
            // tc get locked block or not
            // return Ok(Some(...))
        } else if let Some(ref ss) = self. ss {
            // ss get locked block or not
            // return Ok(Some(...))
        }

        Ok(None)
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

        // Check the embedded PT
        if self.pt != Propose::genesis().pt {
            self.pt.verify(committee)?;
        }

        // Check the embedded QC.
        if self.qc != QC::genesis() {
            self.qc.verify(committee)?;
        }

        // Check the TC/SS embedded in the block. TODO: genesis?
        if self.tc.is_some() && self.ss.is_some() {
            return Err(ConsensusError::TCSSConflict);
        } else if let Some(ref tc) = self.tc {
            tc.verify(committee)?;
        } else if let Some(ref ss) = self.ss {
            ss.verify(committee)?;
        }
        Ok(())
    }
}

impl Hash for Propose {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(self.author.0);
        hasher.update(self.round.to_le_bytes());
        for x in &self.payload {
            hasher.update(x);
        }
        hasher.update(&self.qc.hash);
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Propose {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: B({}, {}, {:?}, {})",
            self.digest(),
            self.author,
            self.round,
            self.qc,
            self.payload.iter().map(|x| x.len()).sum::<usize>(),
        )
    }
}

impl fmt::Display for Propose {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "B{}", self.round)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub hash: Digest,
    pub round: RoundNumber,
    pub author: PublicKey,
    pub signature: Signature,
}

impl Vote {
    pub async fn new(
        block: &Propose,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let vote = Self {
            hash: block.digest(),
            round: block.round,
            author,
            signature: Signature::default(),
        };
        let signature = signature_service.request_signature(vote.digest()).await;
        Self { signature, ..vote }
    }

    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the authority has voting rights.
        ensure!(
            committee.stake(&self.author) > 0,
            ConsensusError::UnknownAuthority(self.author)
        );

        // Check the signature.
        self.signature.verify(&self.digest(), &self.author)?;
        Ok(())
    }
}

impl Hash for Vote {
    fn digest(&self) -> Digest {
        let mut hasher = Sha512::new();
        hasher.update(&self.hash);
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Vote {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "V({}, {}, {})", self.author, self.round, self.hash)
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct QC {
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
        hasher.update(&self.hash);
        hasher.update(self.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for QC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "QC({}, {})", self.hash, self.round)
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
    pub signature: Signature,
}

impl Timeout {
    pub async fn new(
        high_qc: QC,
        round: RoundNumber,
        author: PublicKey,
        mut signature_service: SignatureService,
    ) -> Self {
        let timeout = Self {
            high_qc,
            round,
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
        hasher.update(self.high_qc.round.to_le_bytes());
        Digest(hasher.finalize().as_slice()[..32].try_into().unwrap())
    }
}

impl fmt::Debug for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TV({}, {}, {:?})", self.author, self.round, self.high_qc)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TC {
    pub round: RoundNumber,
    pub votes: Vec<(PublicKey, Signature, RoundNumber)>,
}

impl TC {
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _, _) in self.votes.iter() {
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
        for (author, signature, high_qc_round) in &self.votes {
            let mut hasher = Sha512::new();
            hasher.update(self.round.to_le_bytes());
            hasher.update(high_qc_round.to_le_bytes());
            let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
            signature.verify(&digest, &author)?;
        }
        Ok(())
    }

    pub fn high_qc_rounds(&self) -> Vec<RoundNumber> {
        self.votes.iter().map(|(_, _, r)| r).cloned().collect()
    }
}

impl fmt::Debug for TC {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TC({}, {:?})", self.round, self.high_qc_rounds())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Status {
    pub round: RoundNumber,
    pub votes: Vec<(PublicKey, Signature, RoundNumber)>,
}

impl Status {
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _, _) in self.votes.iter() {
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
        for (author, signature, high_qc_round) in &self.votes {
            let mut hasher = Sha512::new();
            hasher.update(self.round.to_le_bytes());
            hasher.update(high_qc_round.to_le_bytes());
            let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
            signature.verify(&digest, &author)?;
        }
        Ok(())
    }

    pub fn high_qc_rounds(&self) -> Vec<RoundNumber> {
        self.votes.iter().map(|(_, _, r)| r).cloned().collect()
    }
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TC({}, {:?})", self.round, self.high_qc_rounds())
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StatusSet {
    pub round: RoundNumber,
    pub votes: Vec<(PublicKey, Signature, RoundNumber)>,
}

impl StatusSet {
    pub fn verify(&self, committee: &Committee) -> ConsensusResult<()> {
        // Ensure the QC has a quorum.
        let mut weight = 0;
        let mut used = HashSet::new();
        for (name, _, _) in self.votes.iter() {
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
        for (author, signature, high_qc_round) in &self.votes {
            let mut hasher = Sha512::new();
            hasher.update(self.round.to_le_bytes());
            hasher.update(high_qc_round.to_le_bytes());
            let digest = Digest(hasher.finalize().as_slice()[..32].try_into().unwrap());
            signature.verify(&digest, &author)?;
        }
        Ok(())
    }

    pub fn high_qc_rounds(&self) -> Vec<RoundNumber> {
        self.votes.iter().map(|(_, _, r)| r).cloned().collect()
    }
}

impl fmt::Debug for StatusSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "TC({}, {:?})", self.round, self.high_qc_rounds())
    }
}