#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Map, String, Vec};

/// Ledger constants for TTL extension thresholds and bump amounts (~5s per ledger)
/// ~7 days = 120,960 ledgers
pub const INSTANCE_LIFETIME_THRESHOLD: u32 = 120_960;
/// ~30 days = 518,400 ledgers
pub const INSTANCE_BUMP_AMOUNT: u32 = 518_400;
/// ~7 days = 120,960 ledgers
pub const PERSISTENT_LIFETIME_THRESHOLD: u32 = 120_960;
/// ~30 days = 518,400 ledgers
pub const PERSISTENT_BUMP_AMOUNT: u32 = 518_400;

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessLevel {
    Read = 0,
    ReadWrite = 1,
    Admin = 2,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseCondition {
    Anytime = 0,
    LiveOnly = 1,
    EmergencyOnly = 2,
    PostDeathOnly = 3,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestStatus {
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Expired = 3,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Vault {
    pub id: u64,
    pub creator: Address,
    pub name: String,
    pub description: String,
    pub guardians: Vec<Address>,
    pub approval_threshold: u32,
    pub is_active: bool,
    pub created_at: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Document {
    pub id: u64,
    pub vault_id: u64,
    pub encrypted_metadata: String,
    pub ipfs_hash: String,
    pub uploaded_by: Address,
    pub uploaded_at: u64,
    pub required_access: AccessLevel,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct AccessRequest {
    pub request_id: u64,
    pub document_id: u64,
    pub requester: Address,
    pub approved_by: Vec<Address>,
    pub beneficiary_shares: Map<Address, String>,
    pub status: RequestStatus,
    pub expires_at: u64,
    pub created_at: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct GuardianInvite {
    pub guardian: Address,
    pub vault_id: u64,
    pub accepted: bool,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct VaultReleaseState {
    pub emergency_mode: bool,
    pub inactivity_period: u64,
    pub last_proof_of_life: u64,
}

/// Packed per-vault record: combined vault configuration, guardian list
/// (already embedded in `Vault.guardians`) and the vault release state under a
/// single storage key. This consolidates what were previously the `Vault` and
/// `ReleaseState` keys, and removes the redundant per-guardian `IsGuardian`
/// keys entirely (guardianship is derivable from `Vault.guardians`).
#[contracttype]
#[derive(Clone, Debug)]
pub struct VaultRecord {
    pub vault: Vault,
    pub release_state: VaultReleaseState,
}

/// Packed per-document record: combines the document, its release condition,
/// the per-user access grants (replacing the separate `HasAccess`/`AccessLvl`
/// keys), the per-guardian encryption shares (replacing `GShare` keys) and the
/// latest request id per requester (replacing `LatestReq` keys) into a single
/// storage key.
#[contracttype]
#[derive(Clone, Debug)]
pub struct DocumentRecord {
    pub document: Document,
    pub release_condition: ReleaseCondition,
    pub access: Map<Address, AccessLevel>,
    pub shares: Map<Address, String>,
}

#[contracttype]
pub enum DataKey {
    VaultCount,
    DocCount,
    ReqCount,
    VaultRecord(u64),
    DocumentRecord(u64),
    Request(u64),
    Invites(Address),
    PubKey(Address),
    // Cross-Chain Identity Lookup Map
    EvmToStellar(String),
    StellarToEvm(Address),
    EvmToPubKey(String),
}

#[contract]
pub struct SpooVaultStellar;

#[contractimpl]
impl SpooVaultStellar {
    /// Extend instance storage TTL
    pub fn extend_contract_ttl(env: Env) {
        Self::bump_instance(&env);
    }

    /// Extend persistent storage TTL for a vault and its state
    pub fn extend_vault_ttl(env: Env, vault_id: u64) {
        Self::bump_instance(&env);
        let key = DataKey::VaultRecord(vault_id);
        if env.storage().persistent().has(&key) {
            Self::bump_persistent(&env, &key);
        }
    }

    /// Extend persistent storage TTL for a document
    pub fn extend_document_ttl(env: Env, document_id: u64) {
        Self::bump_instance(&env);
        let key = DataKey::DocumentRecord(document_id);
        if env.storage().persistent().has(&key) {
            Self::bump_persistent(&env, &key);
        }
    }

    /// Extend persistent storage TTL for an access request
    pub fn extend_request_ttl(env: Env, request_id: u64) {
        Self::bump_instance(&env);
        let req_key = DataKey::Request(request_id);
        if env.storage().persistent().has(&req_key) {
            Self::bump_persistent(&env, &req_key);
        }
    }

    /// Register a user's encryption public key
    pub fn register_public_key(env: Env, user: Address, public_key: String) {
        user.require_auth();
        Self::bump_instance(&env);

        let key = DataKey::PubKey(user.clone());
        env.storage().persistent().set(&key, &public_key);
        Self::bump_persistent(&env, &key);
    }

    /// Retrieve public key for a user
    pub fn get_public_key(env: Env, user: Address) -> Option<String> {
        Self::bump_instance(&env);
        let key = DataKey::PubKey(user);
        let val: Option<String> = env.storage().persistent().get(&key);
        if val.is_some() {
            Self::bump_persistent(&env, &key);
        }
        val
    }

    /// Register linked cross-chain identity (EVM Address <-> Stellar Address & Public Key)
    pub fn register_cross_chain_identity(
        env: Env,
        stellar_user: Address,
        evm_address: String,
        encryption_pubkey: Option<String>,
    ) {
        stellar_user.require_auth();
        assert!(evm_address.len() == 42, "Invalid EVM address length");
        Self::bump_instance(&env);

        let evm_to_stellar_key = DataKey::EvmToStellar(evm_address.clone());
        let stellar_to_evm_key = DataKey::StellarToEvm(stellar_user.clone());

        env.storage()
            .persistent()
            .set(&evm_to_stellar_key, &stellar_user);
        env.storage()
            .persistent()
            .set(&stellar_to_evm_key, &evm_address);

        Self::bump_persistent(&env, &evm_to_stellar_key);
        Self::bump_persistent(&env, &stellar_to_evm_key);

        if let Some(pubkey) = encryption_pubkey {
            let evm_to_pubkey_key = DataKey::EvmToPubKey(evm_address);
            let stellar_pubkey_key = DataKey::PubKey(stellar_user);

            env.storage().persistent().set(&evm_to_pubkey_key, &pubkey);
            env.storage().persistent().set(&stellar_pubkey_key, &pubkey);

            Self::bump_persistent(&env, &evm_to_pubkey_key);
            Self::bump_persistent(&env, &stellar_pubkey_key);
        }
    }

    /// Resolve EVM address to linked Stellar Address
    pub fn resolve_evm_to_stellar(env: Env, evm_address: String) -> Option<Address> {
        Self::bump_instance(&env);
        let key = DataKey::EvmToStellar(evm_address);
        let addr: Option<Address> = env.storage().persistent().get(&key);
        if addr.is_some() {
            Self::bump_persistent(&env, &key);
        }
        addr
    }

    /// Resolve Stellar Address to linked EVM Address
    pub fn resolve_stellar_to_evm(env: Env, stellar_user: Address) -> Option<String> {
        Self::bump_instance(&env);
        let key = DataKey::StellarToEvm(stellar_user);
        let evm: Option<String> = env.storage().persistent().get(&key);
        if evm.is_some() {
            Self::bump_persistent(&env, &key);
        }
        evm
    }

    /// Resolve EVM address directly to its linked Encryption Public Key
    pub fn resolve_evm_to_public_key(env: Env, evm_address: String) -> Option<String> {
        Self::bump_instance(&env);
        let key = DataKey::EvmToPubKey(evm_address.clone());
        let pubkey: Option<String> = env.storage().persistent().get(&key);
        if pubkey.is_some() {
            Self::bump_persistent(&env, &key);
            return pubkey;
        }

        // Fallback: If EVM -> Stellar exists, resolve Stellar -> PubKey
        if let Some(stellar_addr) = Self::resolve_evm_to_stellar(env.clone(), evm_address) {
            return Self::get_public_key(env, stellar_addr);
        }

        None
    }

    /// Create a new Vault
    pub fn create_vault(
        env: Env,
        creator: Address,
        name: String,
        description: String,
        guardians: Vec<Address>,
        approval_threshold: u32,
    ) -> u64 {
        creator.require_auth();
        Self::bump_instance(&env);

        // Basic validations
        let mut ext_guardian_count = 0;
        let mut processed = Vec::new(&env);

        for i in 0..guardians.len() {
            let guardian = guardians.get(i).unwrap();
            // Check duplicates
            assert!(!processed.contains(&guardian), "Duplicate guardian found");
            processed.push_back(guardian.clone());

            if guardian != creator {
                ext_guardian_count += 1;
            }
        }

        assert!(
            ext_guardian_count > 0,
            "At least one external guardian required"
        );
        let total_guardians = ext_guardian_count + 1;
        assert!(
            approval_threshold > 0 && approval_threshold <= total_guardians,
            "Invalid approval threshold"
        );

        let vault_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::VaultCount)
            .unwrap_or(0);
        let next_vault_id = vault_count + 1;
        env.storage()
            .instance()
            .set(&DataKey::VaultCount, &next_vault_id);

        let mut actual_guardians = Vec::new(&env);
        actual_guardians.push_back(creator.clone());

        let vault = Vault {
            id: next_vault_id,
            creator: creator.clone(),
            name,
            description,
            guardians: actual_guardians,
            approval_threshold,
            is_active: true,
            created_at: env.ledger().timestamp(),
        };

        // Pack vault configuration together with its release state under one key.
        let release_state = VaultReleaseState {
            emergency_mode: false,
            inactivity_period: 30 * 24 * 60 * 60, // 30 days in seconds
            last_proof_of_life: env.ledger().timestamp(),
        };

        let record = VaultRecord {
            vault,
            release_state,
        };

        let record_key = DataKey::VaultRecord(next_vault_id);
        env.storage().persistent().set(&record_key, &record);
        Self::bump_persistent(&env, &record_key);

        // Record invites for external guardians
        for i in 0..guardians.len() {
            let guardian = guardians.get(i).unwrap();
            if guardian == creator {
                continue;
            }

            let invites_key = DataKey::Invites(guardian.clone());
            let mut user_invites: Vec<GuardianInvite> = env
                .storage()
                .persistent()
                .get(&invites_key)
                .unwrap_or_else(|| Vec::new(&env));

            user_invites.push_back(GuardianInvite {
                guardian: guardian.clone(),
                vault_id: next_vault_id,
                accepted: false,
                expires_at: env.ledger().timestamp() + 7 * 24 * 60 * 60, // 7 days
            });

            env.storage().persistent().set(&invites_key, &user_invites);
            Self::bump_persistent(&env, &invites_key);
        }

        next_vault_id
    }

    /// Accept guardian invitation
    pub fn accept_guardian_invite(env: Env, guardian: Address, vault_id: u64) {
        guardian.require_auth();
        Self::bump_instance(&env);

        let record_key = DataKey::VaultRecord(vault_id);
        let mut record: VaultRecord = env
            .storage()
            .persistent()
            .get(&record_key)
            .expect("Vault does not exist");
        assert!(record.vault.is_active, "Vault not active");
        // Guardianship is derivable from the packed guardian list.
        assert!(
            !Self::is_guardian_in_vault(&record.vault, &guardian),
            "Already guardian"
        );

        let invites_key = DataKey::Invites(guardian.clone());
        let mut user_invites: Vec<GuardianInvite> = env
            .storage()
            .persistent()
            .get(&invites_key)
            .expect("No invites for user");

        let mut accepted = false;
        for i in 0..user_invites.len() {
            let mut invite = user_invites.get(i).unwrap();
            if invite.vault_id == vault_id && !invite.accepted {
                assert!(
                    env.ledger().timestamp() < invite.expires_at,
                    "Invite expired"
                );
                invite.accepted = true;
                user_invites.set(i, invite);
                accepted = true;
                break;
            }
        }

        assert!(accepted, "No valid invite found");
        env.storage().persistent().set(&invites_key, &user_invites);
        Self::bump_persistent(&env, &invites_key);

        // Persist guardianship by appending to the packed guardian list.
        record.vault.guardians.push_back(guardian);
        env.storage().persistent().set(&record_key, &record);
        Self::bump_persistent(&env, &record_key);
    }

    /// Add a document metadata and storage hash
    pub fn add_document(
        env: Env,
        uploader: Address,
        vault_id: u64,
        encrypted_metadata: String,
        ipfs_hash: String,
        required_access: AccessLevel,
        release_condition: ReleaseCondition,
        guardians_list: Vec<Address>,
        shares: Vec<String>,
    ) -> u64 {
        uploader.require_auth();
        Self::bump_instance(&env);

        let record_key = DataKey::VaultRecord(vault_id);
        let record: VaultRecord = env
            .storage()
            .persistent()
            .get(&record_key)
            .expect("Vault does not exist");
        assert!(
            Self::is_guardian_in_vault(&record.vault, &uploader),
            "Only guardians can upload documents"
        );
        assert!(ipfs_hash.len() > 0, "IPFS hash required");
        assert!(
            guardians_list.len() == shares.len(),
            "Guardians list and shares count mismatch"
        );

        let doc_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::DocCount)
            .unwrap_or(0);
        let next_doc_id = doc_count + 1;
        env.storage()
            .instance()
            .set(&DataKey::DocCount, &next_doc_id);

        let doc = Document {
            id: next_doc_id,
            vault_id,
            encrypted_metadata,
            ipfs_hash,
            uploaded_by: uploader.clone(),
            uploaded_at: env.ledger().timestamp(),
            required_access,
        };

        // Pack document, release condition, per-user access grants and
        // per-guardian shares into a single storage key.
        let mut access: Map<Address, AccessLevel> = Map::new(&env);
        access.set(uploader.clone(), required_access);

        let mut share_map: Map<Address, String> = Map::new(&env);
        for i in 0..guardians_list.len() {
            let guardian = guardians_list.get(i).unwrap();
            let share = shares.get(i).unwrap();
            share_map.set(guardian, share);
        }

        let doc_record = DocumentRecord {
            document: doc,
            release_condition,
            access,
            shares: share_map,
        };

        let doc_key = DataKey::DocumentRecord(next_doc_id);
        env.storage().persistent().set(&doc_key, &doc_record);
        Self::bump_persistent(&env, &doc_key);

        next_doc_id
    }

    /// Request document access
    pub fn request_access(env: Env, requester: Address, document_id: u64) -> u64 {
        requester.require_auth();
        Self::bump_instance(&env);

        let doc_key = DataKey::DocumentRecord(document_id);
        let doc_record: DocumentRecord = env
            .storage()
            .persistent()
            .get(&doc_key)
            .expect("Document not found");
        Self::bump_persistent(&env, &doc_key);

        assert!(
            !doc_record.access.contains_key(requester.clone()),
            "Already has access"
        );

        // Verify release condition
        assert!(
            Self::is_release_condition_satisfied(
                &env,
                doc_record.document.vault_id,
                doc_record.release_condition
            ),
            "Release condition locked"
        );

        let req_count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ReqCount)
            .unwrap_or(0);
        let next_req_id = req_count + 1;
        env.storage()
            .instance()
            .set(&DataKey::ReqCount, &next_req_id);

        let access_req = AccessRequest {
            request_id: next_req_id,
            document_id,
            requester: requester.clone(),
            approved_by: Vec::new(&env),
            beneficiary_shares: Map::new(&env),
            status: RequestStatus::Pending,
            expires_at: env.ledger().timestamp() + 3 * 24 * 60 * 60, // 3 days
            created_at: env.ledger().timestamp(),
        };

        let req_key = DataKey::Request(next_req_id);
        env.storage().persistent().set(&req_key, &access_req);
        Self::bump_persistent(&env, &req_key);

        next_req_id
    }

    /// Approve document access request by a guardian
    pub fn approve_access(
        env: Env,
        approver: Address,
        request_id: u64,
        beneficiary_share: Option<String>,
    ) {
        approver.require_auth();
        Self::bump_instance(&env);

        let req_key = DataKey::Request(request_id);
        let mut request: AccessRequest = env
            .storage()
            .persistent()
            .get(&req_key)
            .expect("Request not found");
        assert!(
            request.status == RequestStatus::Pending,
            "Request not pending"
        );
        assert!(
            env.ledger().timestamp() < request.expires_at,
            "Request expired"
        );

        let doc_key = DataKey::DocumentRecord(request.document_id);
        let mut doc_record: DocumentRecord = env
            .storage()
            .persistent()
            .get(&doc_key)
            .expect("Document not found");

        let record_key = DataKey::VaultRecord(doc_record.document.vault_id);
        let record: VaultRecord = env
            .storage()
            .persistent()
            .get(&record_key)
            .expect("Vault not found");

        assert!(
            Self::is_guardian_in_vault(&record.vault, &approver),
            "Only guardians can approve access"
        );

        // Approval is derivable from the packed `approved_by` list.
        assert!(!request.approved_by.contains(&approver), "Already approved");

        request.approved_by.push_back(approver.clone());

        if let Some(share) = beneficiary_share {
            request.beneficiary_shares.set(approver, share);
        }

        if request.approved_by.len() >= record.vault.approval_threshold {
            request.status = RequestStatus::Approved;
            doc_record.access.set(
                request.requester.clone(),
                doc_record.document.required_access,
            );
        }

        env.storage().persistent().set(&req_key, &request);
        env.storage().persistent().set(&doc_key, &doc_record);
        Self::bump_persistent(&env, &req_key);
        Self::bump_persistent(&env, &doc_key);
    }

    /// Record proof of life for inactivity check
    pub fn prove_life(env: Env, owner: Address, vault_id: u64) {
        owner.require_auth();
        Self::bump_instance(&env);

        let record_key = DataKey::VaultRecord(vault_id);
        let mut record: VaultRecord = env
            .storage()
            .persistent()
            .get(&record_key)
            .expect("Vault not found");
        assert!(
            record.vault.creator == owner,
            "Only creator can record proof of life"
        );
        assert!(record.vault.is_active, "Vault not active");

        record.release_state.last_proof_of_life = env.ledger().timestamp();
        env.storage().persistent().set(&record_key, &record);

        Self::bump_persistent(&env, &record_key);
    }

    /// Configure vault release conditions
    pub fn configure_vault_release(
        env: Env,
        owner: Address,
        vault_id: u64,
        inactivity_period: u64,
    ) {
        owner.require_auth();
        Self::bump_instance(&env);

        let record_key = DataKey::VaultRecord(vault_id);
        let mut record: VaultRecord = env
            .storage()
            .persistent()
            .get(&record_key)
            .expect("Vault not found");
        assert!(
            record.vault.creator == owner,
            "Only creator can configure release"
        );
        assert!(record.vault.is_active, "Vault not active");
        assert!(
            inactivity_period >= 24 * 60 * 60 && inactivity_period <= 365 * 24 * 60 * 60,
            "Inactivity period must be between 1 and 365 days"
        );

        record.release_state.inactivity_period = inactivity_period;
        env.storage().persistent().set(&record_key, &record);

        Self::bump_persistent(&env, &record_key);
    }

    /// Set vault emergency mode
    pub fn set_emergency_mode(env: Env, owner: Address, vault_id: u64, enabled: bool) {
        owner.require_auth();
        Self::bump_instance(&env);

        let record_key = DataKey::VaultRecord(vault_id);
        let mut record: VaultRecord = env
            .storage()
            .persistent()
            .get(&record_key)
            .expect("Vault not found");
        assert!(
            record.vault.creator == owner,
            "Only creator can set emergency mode"
        );
        assert!(record.vault.is_active, "Vault not active");

        record.release_state.emergency_mode = enabled;
        env.storage().persistent().set(&record_key, &record);

        Self::bump_persistent(&env, &record_key);
    }

    /// Helper function to check if release condition is satisfied
    pub fn is_release_condition_satisfied(
        env: &Env,
        vault_id: u64,
        condition: ReleaseCondition,
    ) -> bool {
        if condition == ReleaseCondition::Anytime {
            return true;
        }

        let record_key = DataKey::VaultRecord(vault_id);
        let record: VaultRecord = env
            .storage()
            .persistent()
            .get(&record_key)
            .expect("Vault state missing");
        Self::bump_persistent(env, &record_key);

        let state = record.release_state;
        let is_dead =
            env.ledger().timestamp() >= state.last_proof_of_life + state.inactivity_period;

        match condition {
            ReleaseCondition::LiveOnly => !is_dead,
            ReleaseCondition::EmergencyOnly => state.emergency_mode || is_dead,
            ReleaseCondition::PostDeathOnly => is_dead,
            ReleaseCondition::Anytime => true,
        }
    }

    pub fn get_vault(env: Env, vault_id: u64) -> Option<Vault> {
        Self::bump_instance(&env);
        let key = DataKey::VaultRecord(vault_id);
        let record: Option<VaultRecord> = env.storage().persistent().get(&key);
        if record.is_some() {
            Self::bump_persistent(&env, &key);
        }
        record.map(|r| r.vault)
    }

    pub fn get_document(env: Env, document_id: u64) -> Option<Document> {
        Self::bump_instance(&env);
        let key = DataKey::DocumentRecord(document_id);
        let record: Option<DocumentRecord> = env.storage().persistent().get(&key);
        if record.is_some() {
            Self::bump_persistent(&env, &key);
        }
        record.map(|r| r.document)
    }

    pub fn get_access_request(env: Env, request_id: u64) -> Option<AccessRequest> {
        Self::bump_instance(&env);
        let key = DataKey::Request(request_id);
        let req: Option<AccessRequest> = env.storage().persistent().get(&key);
        if req.is_some() {
            Self::bump_persistent(&env, &key);
        }
        req
    }

    pub fn get_invites(env: Env, guardian: Address) -> Vec<GuardianInvite> {
        Self::bump_instance(&env);
        let key = DataKey::Invites(guardian);
        let invites: Vec<GuardianInvite> = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| Vec::new(&env));
        if env.storage().persistent().has(&key) {
            Self::bump_persistent(&env, &key);
        }
        invites
    }

    pub fn get_release_state(env: Env, vault_id: u64) -> Option<VaultReleaseState> {
        Self::bump_instance(&env);
        let key = DataKey::VaultRecord(vault_id);
        let record: Option<VaultRecord> = env.storage().persistent().get(&key);
        if record.is_some() {
            Self::bump_persistent(&env, &key);
        }
        record.map(|r| r.release_state)
    }

    // Helper functions for TTL management
    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    fn bump_persistent(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(
            key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    /// Returns true when `addr` is a guardian of `vault`, derived from the
    /// packed guardian list instead of a dedicated per-guardian storage key.
    fn is_guardian_in_vault(vault: &Vault, addr: &Address) -> bool {
        vault.guardians.contains(addr)
    }
}

#[cfg(test)]
mod test;
