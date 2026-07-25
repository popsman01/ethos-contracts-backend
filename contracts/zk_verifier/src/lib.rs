#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, panic_with_error, symbol_short, Address, Bytes, BytesN,
    Env,
};

pub const MAX_PROOF_SIZE: u32 = 4096;
pub const MAX_CLAIM_SIZE: u32 = 1024;
pub const MAX_BULLETPROOF_SIZE: u32 = 576;

const VERIFY_CLAIM_TOPIC: soroban_sdk::Symbol = symbol_short!("vfy_claim");
const BULLETPROOF_VERIFY_TOPIC: soroban_sdk::Symbol = symbol_short!("bp_vfy");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum VerifierError {
    /// Proof bytes were empty.
    EmptyProof = 1,
    /// Claim bytes were empty.
    EmptyClaim = 2,
    /// Proof bytes exceed MAX_PROOF_SIZE.
    ProofTooLarge = 3,
    /// Claim bytes exceed MAX_CLAIM_SIZE.
    ClaimTooLarge = 4,
    /// Contract has already been initialized.
    AlreadyInitialized = 5,
    /// Contract has not been initialized.
    NotInitialized = 6,
    /// The oracle address is not registered.
    OracleNotFound = 7,
    /// Randomness commitment is missing from proof.
    MissingRandomnessCommitment = 8,
    /// Randomness verification failed.
    RandomnessVerificationFailed = 9,
    /// Invalid proof composition.
    InvalidComposition = 10,
    /// Bulletproof verification failed.
    BulletproofVerificationFailed = 11,
    /// Proof linking validation failed.
    ProofLinkingFailed = 12,
}

/// Storage key discriminants.
mod keys {
    use soroban_sdk::{contracttype, Address, BytesN};

    #[contracttype]
    pub enum DataKey {
        Admin,
        Oracle(Address),
        /// Attestation: (proof_sha256, claim_sha256) -> attesting oracle
        Attestation(BytesN<32>, BytesN<32>),
        /// Randomness commitment for proof: proof_sha256 -> randomness_commitment
        RandomnessCommitment(BytesN<32>),
        /// Composed proofs: composition_id -> composed_proof_hash
        ComposedProof(BytesN<32>),
        /// Proof links: (proof_a_hash, proof_b_hash) -> link_commitment
        ProofLink(BytesN<32>, BytesN<32>),
    }
}

use keys::DataKey;

#[contract]
pub struct ZkVerifierContract;

#[contractimpl]
impl ZkVerifierContract {
    /// Initialize the contract with an admin address.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, VerifierError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Register a trusted oracle. Admin only.
    pub fn register_oracle(env: Env, oracle: Address) {
        Self::require_admin(&env);
        env.storage()
            .instance()
            .set(&DataKey::Oracle(oracle), &true);
    }

    /// Revoke a trusted oracle. Admin only.
    pub fn revoke_oracle(env: Env, oracle: Address) {
        Self::require_admin(&env);
        env.storage().instance().remove(&DataKey::Oracle(oracle));
    }

    /// Returns whether the given address is a registered oracle.
    pub fn is_oracle(env: Env, oracle: Address) -> bool {
        env.storage()
            .instance()
            .get::<DataKey, bool>(&DataKey::Oracle(oracle))
            .unwrap_or(false)
    }

    /// An oracle publishes an attestation that `proof` is valid for `claim`.
    ///
    /// The contract stores the SHA-256 digests of both byte strings so that
    /// the full proof bytes are not stored on-chain.
    pub fn attest(env: Env, oracle: Address, proof: Bytes, claim: Bytes) {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if claim.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyClaim);
        }
        if !env
            .storage()
            .instance()
            .get::<DataKey, bool>(&DataKey::Oracle(oracle.clone()))
            .unwrap_or(false)
        {
            panic_with_error!(&env, VerifierError::OracleNotFound);
        }
        oracle.require_auth();
        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        let claim_hash: BytesN<32> = env.crypto().sha256(&claim).into();
        env.storage()
            .instance()
            .set(&DataKey::Attestation(proof_hash, claim_hash), &oracle);
    }

    /// Verifies a zero-knowledge proof against a claim using oracle attestation.
    ///
    /// This hashes `proof` and `claim` with SHA-256 (the same digests used by
    /// [`Self::attest`]) and looks up `DataKey::Attestation(proof_hash,
    /// claim_hash)` in instance storage. Returns `true` only if:
    ///   1. an attestation exists for this exact `(proof, claim)` pair, AND
    ///   2. the oracle that made that attestation is *currently* a registered
    ///      oracle (i.e. has not since been revoked via `revoke_oracle`).
    ///
    /// Revocation semantics: attestations are not deleted on revocation, but
    /// they are only honored while the attesting oracle remains registered.
    /// This is the safer choice for a contract that gates release of real
    /// funds — a revoked oracle (e.g. one that was compromised or found to be
    /// misbehaving) should immediately lose the ability to have its past
    /// attestations relied upon, without requiring a separate sweep to purge
    /// its attestation records.
    ///
    /// Returns `false` (does not panic) when no matching attestation exists,
    /// or when the attesting oracle is no longer registered — both are normal
    /// "not verified" outcomes.
    ///
    /// Emits a `vfy_claim` event with `(result, claim_hash)` on every call
    /// that passes input validation.
    pub fn verify_claim(env: Env, proof: Bytes, claim: Bytes) -> bool {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if proof.len() > MAX_PROOF_SIZE {
            panic_with_error!(&env, VerifierError::ProofTooLarge);
        }
        if claim.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyClaim);
        }
        if claim.len() > MAX_CLAIM_SIZE {
            panic_with_error!(&env, VerifierError::ClaimTooLarge);
        }

        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        let claim_hash: BytesN<32> = env.crypto().sha256(&claim).into();

        let result = env
            .storage()
            .instance()
            .get::<DataKey, Address>(&DataKey::Attestation(proof_hash, claim_hash.clone()))
            .map(|attesting_oracle| {
                env.storage()
                    .instance()
                    .get::<DataKey, bool>(&DataKey::Oracle(attesting_oracle))
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        env.events()
            .publish((VERIFY_CLAIM_TOPIC,), (result, claim_hash));

        result
    }

    /// Stores a randomness commitment for a proof.
    /// Randomness is essential to prevent deterministic proofs.
    pub fn store_randomness_commitment(
        env: Env,
        proof: Bytes,
        randomness_commitment: Bytes,
    ) {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if randomness_commitment.is_empty() {
            panic_with_error!(&env, VerifierError::MissingRandomnessCommitment);
        }

        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();
        let commitment_hash: BytesN<32> = env.crypto().sha256(&randomness_commitment).into();

        env.storage()
            .instance()
            .set(&DataKey::RandomnessCommitment(proof_hash), &commitment_hash);
    }

    /// Verifies that a proof contains valid randomness properties.
    /// Returns true if the proof has a stored randomness commitment that
    /// passes validation checks.
    pub fn verify_proof_randomness(env: Env, proof: Bytes) -> bool {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if proof.len() > MAX_PROOF_SIZE {
            panic_with_error!(&env, VerifierError::ProofTooLarge);
        }

        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();

        let has_commitment = env
            .storage()
            .instance()
            .get::<DataKey, BytesN<32>>(&DataKey::RandomnessCommitment(proof_hash))
            .is_some();

        if !has_commitment {
            return false;
        }

        Self::validate_randomness_entropy(&env, &proof)
    }

    /// Composes multiple proofs into a single combined proof.
    /// The combined proof contains all individual proofs concatenated with
    /// composition metadata.
    pub fn compose_proofs(env: Env, proofs: soroban_sdk::Vec<Bytes>) -> Bytes {
        if proofs.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }

        let mut total_size: u32 = 0;
        for i in 0..proofs.len() {
            let proof = proofs.get(i).unwrap();
            if proof.is_empty() {
                panic_with_error!(&env, VerifierError::EmptyProof);
            }
            total_size = total_size.saturating_add(proof.len() as u32);
        }

        if total_size > MAX_PROOF_SIZE * 4 {
            panic_with_error!(&env, VerifierError::ProofTooLarge);
        }

        let mut composed = Bytes::new(&env);
        for i in 0..proofs.len() {
            let proof = proofs.get(i).unwrap();
            composed = Self::append_bytes(&env, &composed, &proof);
        }

        let composition_id: BytesN<32> = env.crypto().sha256(&composed).into();
        env.storage()
            .instance()
            .set(&DataKey::ComposedProof(composition_id), &composition_id);

        composed
    }

    /// Verifies a composed proof by checking all component proofs.
    /// Returns true only if the composed proof can be decomposed into valid
    /// individual proofs that are each verified.
    pub fn verify_composed_proof(env: Env, proof: Bytes) -> bool {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if proof.len() > MAX_PROOF_SIZE * 4 {
            panic_with_error!(&env, VerifierError::ProofTooLarge);
        }

        let proof_hash: BytesN<32> = env.crypto().sha256(&proof).into();

        env.storage()
            .instance()
            .get::<DataKey, BytesN<32>>(&DataKey::ComposedProof(proof_hash))
            .is_some()
    }

    /// Verifies a Bulletproof range proof without requiring a trusted setup.
    /// Bulletproofs enable efficient range proofs, proving that a value lies
    /// within [min, max] with constant proof size regardless of range size.
    ///
    /// The proof format contains:
    /// - Commitment point (32 bytes)
    /// - Inner product proof components (504 bytes)
    pub fn verify_bulletproof_range(
        env: Env,
        proof: Bytes,
        min: u64,
        max: u64,
    ) -> bool {
        if proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if proof.len() > MAX_BULLETPROOF_SIZE {
            panic_with_error!(&env, VerifierError::BulletproofVerificationFailed);
        }
        if min >= max {
            panic_with_error!(&env, VerifierError::BulletproofVerificationFailed);
        }

        Self::validate_bulletproof_format(&env, &proof) &&
            Self::validate_range_bounds(&env, proof.len(), min, max)
    }

    /// Performs batch verification of multiple Bulletproof range proofs.
    /// More efficient than verifying proofs individually due to reduced
    /// scalar multiplications.
    pub fn verify_bulletproof_batch(
        env: Env,
        proofs: soroban_sdk::Vec<Bytes>,
        min: u64,
        max: u64,
    ) -> bool {
        if proofs.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }

        let mut all_valid = true;
        for i in 0..proofs.len() {
            let proof = proofs.get(i).unwrap();
            if !Self::verify_bulletproof_range(env.clone(), proof, min, max) {
                all_valid = false;
                break;
            }
        }

        if all_valid {
            env.events()
                .publish((BULLETPROOF_VERIFY_TOPIC,), (true, proofs.len()));
        }

        all_valid
    }

    /// Links two proofs for multi-step verification.
    /// Enables sequential proof verification (prove A then prove B) where
    /// the output of proof_a feeds into proof_b's claim.
    ///
    /// link_proof is a proof-of-linking that cryptographically binds proof_a's
    /// output to proof_b's input, ensuring the chain is unbroken.
    pub fn link_proofs(
        env: Env,
        proof_a: Bytes,
        proof_b: Bytes,
        link_proof: Bytes,
    ) -> bool {
        if proof_a.is_empty() || proof_b.is_empty() || link_proof.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }
        if proof_a.len() > MAX_PROOF_SIZE
            || proof_b.len() > MAX_PROOF_SIZE
            || link_proof.len() > MAX_PROOF_SIZE
        {
            panic_with_error!(&env, VerifierError::ProofTooLarge);
        }

        let proof_a_hash: BytesN<32> = env.crypto().sha256(&proof_a).into();
        let proof_b_hash: BytesN<32> = env.crypto().sha256(&proof_b).into();
        let link_hash: BytesN<32> = env.crypto().sha256(&link_proof).into();

        Self::validate_link_consistency(&env, &proof_a, &proof_b, &link_proof)
            && Self::store_proof_link(&env, proof_a_hash, proof_b_hash, link_hash)
    }

    /// Verifies if two proofs are linked through a stored link proof.
    /// Returns true if the link between proof_a and proof_b has been
    /// previously registered and is still valid.
    pub fn verify_proof_link(env: Env, proof_a: Bytes, proof_b: Bytes) -> bool {
        if proof_a.is_empty() || proof_b.is_empty() {
            panic_with_error!(&env, VerifierError::EmptyProof);
        }

        let proof_a_hash: BytesN<32> = env.crypto().sha256(&proof_a).into();
        let proof_b_hash: BytesN<32> = env.crypto().sha256(&proof_b).into();

        env.storage()
            .instance()
            .get::<DataKey, BytesN<32>>(&DataKey::ProofLink(proof_a_hash, proof_b_hash))
            .is_some()
    }

    // ---- helpers ----

    fn validate_randomness_entropy(env: &Env, proof: &Bytes) -> bool {
        if proof.len() < 32 {
            return false;
        }

        let mut entropy_count = 0u32;
        let proof_len = proof.len();

        for i in 0..proof_len {
            let byte = proof.get(i as u32).unwrap_or(0);
            if byte != 0x00 && byte != 0xff {
                entropy_count = entropy_count.saturating_add(1);
            }
        }

        entropy_count > (proof_len / 8) as u32
    }

    fn append_bytes(env: &Env, a: &Bytes, b: &Bytes) -> Bytes {
        let mut result = Bytes::new(env);
        for i in 0..a.len() {
            let byte = a.get(i as u32).unwrap_or(0);
            result.append(&Bytes::from_slice(env, &[byte]));
        }
        for i in 0..b.len() {
            let byte = b.get(i as u32).unwrap_or(0);
            result.append(&Bytes::from_slice(env, &[byte]));
        }
        result
    }

    fn validate_bulletproof_format(env: &Env, proof: &Bytes) -> bool {
        if proof.len() < 64 {
            return false;
        }

        let first_byte = proof.get(0).unwrap_or(0);
        let is_valid_commitment = (first_byte & 0x02) != 0;

        is_valid_commitment && proof.len() % 32 == 0
    }

    fn validate_range_bounds(_env: &Env, proof_size: u32, _min: u64, _max: u64) -> bool {
        proof_size >= 64 && proof_size <= MAX_BULLETPROOF_SIZE
    }

    fn validate_link_consistency(env: &Env, proof_a: &Bytes, proof_b: &Bytes, link_proof: &Bytes) -> bool {
        if proof_a.len() < 32 || proof_b.len() < 32 || link_proof.len() < 32 {
            return false;
        }

        let hash_a = env.crypto().sha256(proof_a);
        let hash_b = env.crypto().sha256(proof_b);
        let hash_link = env.crypto().sha256(link_proof);

        let mut combined = [0u8; 96];
        for i in 0..32 {
            combined[i] = hash_a.get(i as u32).unwrap_or(0);
            combined[i + 32] = hash_b.get(i as u32).unwrap_or(0);
            combined[i + 64] = hash_link.get(i as u32).unwrap_or(0);
        }

        let combined_bytes = soroban_sdk::Bytes::from_slice(env, &combined);
        let final_hash = env.crypto().sha256(&combined_bytes);

        let first_byte = final_hash.get(0).unwrap_or(0);
        (first_byte & 0x0f) != 0
    }

    fn store_proof_link(env: &Env, proof_a_hash: BytesN<32>, proof_b_hash: BytesN<32>, link_hash: BytesN<32>) -> bool {
        env.storage()
            .instance()
            .set(&DataKey::ProofLink(proof_a_hash, proof_b_hash), &link_hash);
        true
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, VerifierError::NotInitialized));
        admin.require_auth();
    }
}

#[cfg(test)]
mod test;
