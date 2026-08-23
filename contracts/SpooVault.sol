// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "./interfaces/ISpooVault.sol";

/**
 * @title SpooVault
 * @dev NFT-powered multi-signature encrypted document vault with ERC-165 standard access delegation interface.
 */
contract SpooVault is ERC721, ISpooVault {
    uint256 private _tokenIdCounter;
    uint256 private _vaultIdCounter;
    uint256 private _documentIdCounter;
    uint256 private _requestIdCounter;

    error AtLeastOneGuardian();
    error InvalidApprovalThreshold();
    error VaultNotActive();
    error OnlyGuardian();
    error IPFSHashRequired();
    error DocumentNotExist();
    error AlreadyHasAccess();
    error NFTRequired();
    error RequestNotExist();
    error RequestNotPending();
    error RequestExpired();
    error RequestAlreadyPending();
    error AlreadyApproved();
    error NoValidInvite();
    error InviteExpired();
    error NotOwnerOrApproved();
    error ZeroAddressGuardian();
    error DuplicateGuardian();
    error AlreadyGuardian();
    error OnlyVaultCreator();
    error InvalidInactivityPeriod();
    error VaultNotExist();
    error ReleaseConditionLocked();

    mapping(uint256 => Vault) public vaults;
    mapping(uint256 => Document) public documents;
    mapping(uint256 => AccessRequest) public accessRequests;
    mapping(uint256 => mapping(address => bool)) public isGuardian;
    mapping(uint256 => mapping(address => bool)) public hasAccess;
    mapping(uint256 => mapping(address => AccessLevel)) public userAccessLevel;
    mapping(address => GuardianInvite[]) public guardianInvites;
    mapping(uint256 => mapping(address => bool)) public hasApprovedRequest;
    mapping(uint256 => mapping(address => uint256)) public latestRequestId;
    mapping(uint256 => string) public tokenURIs;
    mapping(uint256 => uint256) private tokenVaultMapping;
    mapping(address => mapping(uint256 => uint256)) private _ownedVaultTokenBalance;
    uint256 private _activeTokenSupply;
    mapping(uint256 => ReleaseCondition) public documentReleaseCondition;

    // ECIES and SSS specific mappings
    mapping(address => string) public userPublicKeys;
    // documentId => guardianAddress => encryptedShare
    mapping(uint256 => mapping(address => string)) public encryptedGuardianShares;
    // requestId => guardianAddress => encryptedShareForBeneficiary
    mapping(uint256 => mapping(address => string)) public beneficiaryKeyShares;

    // Access versions let us invalidate all prior document grants for a user+vault in O(1).
    mapping(uint256 => mapping(address => uint256)) private _vaultAccessVersion;
    mapping(uint256 => mapping(address => uint256)) private _documentAccessVersion;
    mapping(uint256 => VaultReleaseState) private _vaultReleaseStates;

    /**
     * @notice Register ECIES public key for a user address.
     * @param publicKey ECIES public key string.
     */
    function registerPublicKey(string calldata publicKey) external override {
        userPublicKeys[msg.sender] = publicKey;
        emit PublicKeyRegistered(msg.sender, publicKey);
    }

    /**
     * @notice Retrieve encrypted key share saved for a guardian.
     * @param documentId ID of the document.
     * @param guardian Address of the guardian.
     */
    function getEncryptedGuardianShare(uint256 documentId, address guardian) external view returns (string memory) {
        return encryptedGuardianShares[documentId][guardian];
    }

    /**
     * @notice Retrieve encrypted key share submitted for a beneficiary.
     * @param requestId ID of the access request.
     * @param guardian Address of the guardian.
     */
    function getBeneficiaryKeyShare(uint256 requestId, address guardian) external view returns (string memory) {
        return beneficiaryKeyShares[requestId][guardian];
    }

    constructor() ERC721("SpooVault Access Token", "SPVT") {}

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721, IERC165) returns (bool) {
        return interfaceId == type(ISpooVault).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @notice Standardized cross-contract document access check returning status codes.
     * @param documentId The ID of the document to inspect.
     * @param user The address of the user or contract inquiring access.
     * @return 0 = GRANTED, 1 = DOCUMENT_NOT_EXIST, 2 = NO_ACCESS, 3 = RELEASE_CONDITION_LOCKED.
     */
    function checkAccess(uint256 documentId, address user) external view override returns (uint8) {
        if (documents[documentId].id == 0) {
            return uint8(AccessCheckResult.DOCUMENT_NOT_EXIST);
        }
        if (!_isReleaseConditionSatisfied(documentId)) {
            return uint8(AccessCheckResult.RELEASE_CONDITION_LOCKED);
        }
        if (!_hasActiveAccess(documentId, user)) {
            return uint8(AccessCheckResult.NO_ACCESS);
        }
        return uint8(AccessCheckResult.GRANTED);
    }

    /**
     * @dev Create a new vault with guardian invites.
     * msg.sender becomes the first active guardian.
     */
    function createVault(
        string memory name,
        string memory description,
        address[] memory guardians,
        uint256 approvalThreshold
    ) external returns (uint256) {
        uint256 externalGuardianCount = 0;

        for (uint256 i = 0; i < guardians.length; i++) {
            address guardian = guardians[i];
            if (guardian == address(0)) revert ZeroAddressGuardian();

            for (uint256 j = 0; j < i; j++) {
                if (guardians[j] == guardian) revert DuplicateGuardian();
            }

            if (guardian != msg.sender) {
                externalGuardianCount++;
            }
        }

        if (externalGuardianCount == 0) revert AtLeastOneGuardian();

        uint256 totalGuardianCount = externalGuardianCount + 1;
        if (approvalThreshold == 0 || approvalThreshold > totalGuardianCount) {
            revert InvalidApprovalThreshold();
        }

        _vaultIdCounter += 1;
        uint256 vaultId = _vaultIdCounter;

        Vault storage newVault = vaults[vaultId];
        newVault.id = vaultId;
        newVault.creator = msg.sender;
        newVault.name = name;
        newVault.description = description;
        newVault.approvalThreshold = approvalThreshold;
        newVault.isActive = true;
        newVault.createdAt = block.timestamp;

        _vaultReleaseStates[vaultId] = VaultReleaseState({
            emergencyMode: false,
            inactivityPeriod: 30 days,
            lastProofOfLife: block.timestamp
        });

        newVault.guardians.push(msg.sender);
        isGuardian[vaultId][msg.sender] = true;

        for (uint256 i = 0; i < guardians.length; i++) {
            address guardian = guardians[i];
            if (guardian == msg.sender) {
                continue;
            }

            guardianInvites[guardian].push(
                GuardianInvite({
                    guardian: guardian,
                    vaultId: vaultId,
                    accepted: false,
                    expiresAt: block.timestamp + 7 days
                })
            );
        }

        emit VaultCreated(vaultId, msg.sender, name);
        return vaultId;
    }

    /**
     * @dev Accept a guardian invitation. Guardian power is granted only after acceptance.
     */
    function acceptGuardianInvite(uint256 vaultId) external {
        if (!vaults[vaultId].isActive) revert VaultNotActive();
        if (isGuardian[vaultId][msg.sender]) revert AlreadyGuardian();

        GuardianInvite[] storage invites = guardianInvites[msg.sender];
        bool hasInvite = false;
        bool hasExpiredInvite = false;

        for (uint256 i = 0; i < invites.length; i++) {
            GuardianInvite storage invite = invites[i];
            if (invite.vaultId != vaultId || invite.accepted) {
                continue;
            }

            hasInvite = true;

            if (invite.expiresAt <= block.timestamp) {
                hasExpiredInvite = true;
                continue;
            }

            invite.accepted = true;
            isGuardian[vaultId][msg.sender] = true;
            vaults[vaultId].guardians.push(msg.sender);

            emit GuardianAdded(vaultId, msg.sender);
            return;
        }

        if (hasExpiredInvite) revert InviteExpired();
        if (!hasInvite) revert NoValidInvite();
    }

    /**
     * @dev Add document metadata and encrypted content reference.
     */
    function addDocument(
        uint256 vaultId,
        string memory encryptedMetadata,
        string memory ipfsHash,
        AccessLevel requiredAccess
    ) external returns (uint256) {
        address[] memory emptyGuardians;
        string[] memory emptyShares;
        return _addDocument(
            vaultId,
            encryptedMetadata,
            ipfsHash,
            requiredAccess,
            ReleaseCondition.ANYTIME,
            emptyGuardians,
            emptyShares
        );
    }

    /**
     * @dev Add document with explicit release condition policy.
     */
    function addDocumentWithReleaseCondition(
        uint256 vaultId,
        string memory encryptedMetadata,
        string memory ipfsHash,
        AccessLevel requiredAccess,
        ReleaseCondition releaseCondition
    ) external returns (uint256) {
        address[] memory emptyGuardians;
        string[] memory emptyShares;
        return _addDocument(
            vaultId,
            encryptedMetadata,
            ipfsHash,
            requiredAccess,
            releaseCondition,
            emptyGuardians,
            emptyShares
        );
    }

    /**
     * @dev Add document with ECIES-encrypted guardian shares.
     */
    function addDocument(
        uint256 vaultId,
        string memory encryptedMetadata,
        string memory ipfsHash,
        AccessLevel requiredAccess,
        address[] calldata guardiansList,
        string[] calldata shares
    ) external returns (uint256) {
        return _addDocument(
            vaultId,
            encryptedMetadata,
            ipfsHash,
            requiredAccess,
            ReleaseCondition.ANYTIME,
            guardiansList,
            shares
        );
    }

    /**
     * @dev Add document with release condition policy and ECIES-encrypted guardian shares.
     */
    function addDocumentWithReleaseCondition(
        uint256 vaultId,
        string memory encryptedMetadata,
        string memory ipfsHash,
        AccessLevel requiredAccess,
        ReleaseCondition releaseCondition,
        address[] calldata guardiansList,
        string[] calldata shares
    ) external returns (uint256) {
        return _addDocument(
            vaultId,
            encryptedMetadata,
            ipfsHash,
            requiredAccess,
            releaseCondition,
            guardiansList,
            shares
        );
    }

    /**
     * @dev Configure how long owner inactivity unlocks post-death mode.
     */
    function configureVaultRelease(uint256 vaultId, uint256 inactivityPeriod) external {
        if (vaults[vaultId].id == 0) revert VaultNotExist();
        if (vaults[vaultId].creator != msg.sender) revert OnlyVaultCreator();
        if (!vaults[vaultId].isActive) revert VaultNotActive();
        if (inactivityPeriod < 1 days || inactivityPeriod > 365 days) {
            revert InvalidInactivityPeriod();
        }

        _vaultReleaseStates[vaultId].inactivityPeriod = inactivityPeriod;
        emit VaultReleaseConfigured(vaultId, inactivityPeriod);
    }

    /**
     * @dev Owner heartbeat to keep vault in live mode.
     */
    function proveLife(uint256 vaultId) external {
        if (vaults[vaultId].id == 0) revert VaultNotExist();
        if (vaults[vaultId].creator != msg.sender) revert OnlyVaultCreator();
        if (!vaults[vaultId].isActive) revert VaultNotActive();

        _vaultReleaseStates[vaultId].lastProofOfLife = block.timestamp;
        emit ProofOfLifeRecorded(vaultId, msg.sender, block.timestamp);
    }

    /**
     * @dev Owner can toggle emergency mode for rapid release workflows.
     */
    function setEmergencyMode(uint256 vaultId, bool enabled) external {
        if (vaults[vaultId].id == 0) revert VaultNotExist();
        if (vaults[vaultId].creator != msg.sender) revert OnlyVaultCreator();
        if (!vaults[vaultId].isActive) revert VaultNotActive();

        _vaultReleaseStates[vaultId].emergencyMode = enabled;
        emit EmergencyModeUpdated(vaultId, enabled);
    }

    /**
     * @dev Guardians can update an existing document release condition.
     */
    function setDocumentReleaseCondition(
        uint256 documentId,
        ReleaseCondition condition
    ) external {
        if (documents[documentId].id == 0) revert DocumentNotExist();
        uint256 vaultId = documents[documentId].vaultId;
        if (!isGuardian[vaultId][msg.sender]) revert OnlyGuardian();

        documentReleaseCondition[documentId] = condition;
        emit DocumentReleaseConditionSet(documentId, condition);
    }

    /**
     * @dev Fetch vault release state summary.
     */
    function getVaultReleaseState(uint256 vaultId) external view override returns (
        bool emergencyMode,
        uint256 inactivityPeriod,
        uint256 lastProofOfLife,
        bool postDeathUnlocked
    ) {
        if (vaults[vaultId].id == 0) revert VaultNotExist();
        VaultReleaseState storage state = _vaultReleaseStates[vaultId];
        bool unlocked = _isPostDeathUnlocked(vaultId);
        return (
            state.emergencyMode,
            state.inactivityPeriod,
            state.lastProofOfLife,
            unlocked
        );
    }

    function _addDocument(
        uint256 vaultId,
        string memory encryptedMetadata,
        string memory ipfsHash,
        AccessLevel requiredAccess,
        ReleaseCondition releaseCondition,
        address[] memory guardiansList,
        string[] memory shares
    ) internal returns (uint256) {
        if (!vaults[vaultId].isActive) revert VaultNotActive();
        if (!isGuardian[vaultId][msg.sender]) revert OnlyGuardian();
        if (bytes(ipfsHash).length == 0) revert IPFSHashRequired();

        _documentIdCounter += 1;
        uint256 documentId = _documentIdCounter;

        documents[documentId] = Document({
            id: documentId,
            vaultId: vaultId,
            encryptedMetadata: encryptedMetadata,
            ipfsHash: ipfsHash,
            uploadedBy: msg.sender,
            uploadedAt: block.timestamp,
            requiredAccess: requiredAccess
        });

        documentReleaseCondition[documentId] = releaseCondition;
        _grantAccess(0, documentId, msg.sender);

        for (uint256 i = 0; i < guardiansList.length; i++) {
            encryptedGuardianShares[documentId][guardiansList[i]] = shares[i];
        }

        emit DocumentAdded(documentId, vaultId, ipfsHash);
        emit DocumentReleaseConditionSet(documentId, releaseCondition);
        if (guardiansList.length > 0) {
            emit GuardianSharesSaved(documentId);
        }
        return documentId;
    }

    /**
     * @dev Request access to a document. Requires current ownership of a vault NFT.
     */
    function requestAccess(uint256 documentId) external override returns (uint256) {
        if (documents[documentId].id == 0) revert DocumentNotExist();
        if (_hasActiveAccess(documentId, msg.sender)) revert AlreadyHasAccess();
        if (!_isReleaseConditionSatisfied(documentId)) revert ReleaseConditionLocked();

        uint256 vaultId = documents[documentId].vaultId;
        if (!_ownsVaultToken(msg.sender, vaultId)) revert NFTRequired();

        uint256 existingRequestId = latestRequestId[documentId][msg.sender];
        if (existingRequestId != 0) {
            AccessRequest storage existingRequest = accessRequests[existingRequestId];
            if (
                existingRequest.status == RequestStatus.PENDING &&
                existingRequest.expiresAt > block.timestamp
            ) {
                revert RequestAlreadyPending();
            }
        }

        _requestIdCounter += 1;
        uint256 requestId = _requestIdCounter;

        accessRequests[requestId] = AccessRequest({
            requestId: requestId,
            documentId: documentId,
            requester: msg.sender,
            approvedBy: new address[](0),
            status: RequestStatus.PENDING,
            expiresAt: block.timestamp + 3 days,
            createdAt: block.timestamp
        });

        latestRequestId[documentId][msg.sender] = requestId;

        emit AccessRequested(requestId, documentId, msg.sender);
        return requestId;
    }

    /**
     * @dev Approve an access request (guardian only).
     */
    function approveAccess(uint256 requestId) external override {
        _approveAccess(requestId, "");
    }

    /**
     * @dev Approve an access request and submit the decrypted key share for the beneficiary.
     */
    function approveAccess(uint256 requestId, string calldata encryptedShareForBeneficiary) external override {
        _approveAccess(requestId, encryptedShareForBeneficiary);
    }

    function _approveAccess(uint256 requestId, string memory encryptedShareForBeneficiary) internal {
        AccessRequest storage request = accessRequests[requestId];
        if (request.requestId == 0) revert RequestNotExist();
        if (request.status != RequestStatus.PENDING) revert RequestNotPending();
        if (request.expiresAt <= block.timestamp) revert RequestExpired();

        uint256 vaultId = documents[request.documentId].vaultId;
        if (!isGuardian[vaultId][msg.sender]) revert OnlyGuardian();
        if (hasApprovedRequest[requestId][msg.sender]) revert AlreadyApproved();

        hasApprovedRequest[requestId][msg.sender] = true;
        request.approvedBy.push(msg.sender);

        if (bytes(encryptedShareForBeneficiary).length > 0) {
            beneficiaryKeyShares[requestId][msg.sender] = encryptedShareForBeneficiary;
            emit ShareSubmittedForBeneficiary(requestId, msg.sender, encryptedShareForBeneficiary);
        }

        emit AccessApproved(requestId, msg.sender);

        if (request.approvedBy.length >= vaults[vaultId].approvalThreshold) {
            if (!_ownsVaultToken(request.requester, vaultId)) {
                request.status = RequestStatus.REJECTED;
                return;
            }

            request.status = RequestStatus.APPROVED;
            _grantAccess(requestId, request.documentId, request.requester);
        }
    }

    /**
     * @dev Revoke access from user for a specific document.
     */
    function revokeAccess(uint256 documentId, address user) external override {
        if (documents[documentId].id == 0) revert DocumentNotExist();

        uint256 vaultId = documents[documentId].vaultId;
        if (!isGuardian[vaultId][msg.sender]) revert OnlyGuardian();

        hasAccess[documentId][user] = false;
        delete userAccessLevel[documentId][user];
        delete _documentAccessVersion[documentId][user];

        emit AccessRevoked(documentId, user);
    }

    /**
     * @dev Mint NFT access token for a vault.
     */
    function mintAccessToken(
        uint256 vaultId,
        address to,
        string memory tokenURIValue
    ) external override returns (uint256) {
        if (!vaults[vaultId].isActive) revert VaultNotActive();
        if (!isGuardian[vaultId][msg.sender]) revert OnlyGuardian();

        _tokenIdCounter += 1;
        uint256 tokenId = _tokenIdCounter;

        tokenVaultMapping[tokenId] = vaultId;
        _safeMint(to, tokenId);
        tokenURIs[tokenId] = tokenURIValue;

        emit NFTMinted(tokenId, to, vaultId);
        return tokenId;
    }

    /**
     * @dev Burn NFT access token and invalidate all prior grants for owner+vault in O(1).
     */
    function burnAccessToken(uint256 tokenId) external override {
        address owner = ownerOf(tokenId);
        if (!_isTokenOwnerOrApproved(owner, msg.sender, tokenId)) {
            revert NotOwnerOrApproved();
        }

        uint256 vaultId = tokenVaultMapping[tokenId];
        _vaultAccessVersion[vaultId][owner] = _currentAccessVersion(vaultId, owner) + 1;

        _burn(tokenId);

        delete tokenVaultMapping[tokenId];
        delete tokenURIs[tokenId];

        emit NFTBurned(tokenId);
    }

    /**
     * @dev Get vault details.
     */
    function getVault(uint256 vaultId) external view override returns (
        uint256 id,
        address creator,
        string memory name,
        string memory description,
        address[] memory guardians,
        uint256 approvalThreshold,
        bool isActive,
        uint256 createdAt
    ) {
        Vault storage vault = vaults[vaultId];
        return (
            vault.id,
            vault.creator,
            vault.name,
            vault.description,
            vault.guardians,
            vault.approvalThreshold,
            vault.isActive,
            vault.createdAt
        );
    }

    /**
     * @dev Get user's pending invites.
     */
    function getPendingInvites(address user) external view returns (GuardianInvite[] memory) {
        GuardianInvite[] storage invites = guardianInvites[user];
        uint256 count = 0;

        for (uint256 i = 0; i < invites.length; i++) {
            if (!invites[i].accepted && invites[i].expiresAt > block.timestamp) {
                count++;
            }
        }

        GuardianInvite[] memory pending = new GuardianInvite[](count);
        uint256 index = 0;

        for (uint256 i = 0; i < invites.length; i++) {
            if (!invites[i].accepted && invites[i].expiresAt > block.timestamp) {
                pending[index] = invites[i];
                index++;
            }
        }

        return pending;
    }

    /**
     * @dev Return vault id attached to token id (0 if missing/deleted).
     */
    function getTokenVault(uint256 tokenId) external view override returns (uint256) {
        return tokenVaultMapping[tokenId];
    }

    /**
     * @dev Returns whether user currently holds any token for vault.
     */
    function hasVaultToken(address user, uint256 vaultId) external view override returns (bool) {
        return _ownsVaultToken(user, vaultId);
    }

    /**
     * @dev Returns effective access, tied to both granted access and live vault token ownership.
     */
    function hasActiveAccess(uint256 documentId, address user) external view override returns (bool) {
        if (documents[documentId].id == 0) {
            return false;
        }
        return _hasActiveAccess(documentId, user);
    }

    /**
     * @dev Total active NFT supply (minted - burned).
     */
    function totalSupply() external view returns (uint256) {
        return _activeTokenSupply;
    }

    /**
     * @dev Return token URI from storage mapping.
     */
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        ownerOf(tokenId);
        return tokenURIs[tokenId];
    }

    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = super._update(to, tokenId, auth);
        uint256 vaultId = tokenVaultMapping[tokenId];

        if (from == address(0)) {
            _activeTokenSupply += 1;
        } else if (vaultId != 0 && _ownedVaultTokenBalance[from][vaultId] > 0) {
            _ownedVaultTokenBalance[from][vaultId] -= 1;
        }

        if (to == address(0)) {
            if (_activeTokenSupply > 0) {
                _activeTokenSupply -= 1;
            }
        } else if (vaultId != 0) {
            _ownedVaultTokenBalance[to][vaultId] += 1;
            if (_vaultAccessVersion[vaultId][to] == 0) {
                _vaultAccessVersion[vaultId][to] = 1;
            }
        }

        return from;
    }

    function _grantAccess(uint256 requestId, uint256 documentId, address user) internal {
        uint256 vaultId = documents[documentId].vaultId;
        uint256 currentVersion = _currentAccessVersion(vaultId, user);

        hasAccess[documentId][user] = true;
        _documentAccessVersion[documentId][user] = currentVersion;
        userAccessLevel[documentId][user] = documents[documentId].requiredAccess;

        emit AccessGranted(requestId, documentId, user);
    }

    function _hasActiveAccess(uint256 documentId, address user) internal view returns (bool) {
        uint256 vaultId = documents[documentId].vaultId;
        if (isGuardian[vaultId][user]) {
            return true;
        }

        if (!hasAccess[documentId][user]) {
            return false;
        }

        if (!_ownsVaultToken(user, vaultId)) {
            return false;
        }

        return _documentAccessVersion[documentId][user] == _currentAccessVersion(vaultId, user);
    }

    function _currentAccessVersion(uint256 vaultId, address user) internal view returns (uint256) {
        uint256 version = _vaultAccessVersion[vaultId][user];
        return version == 0 ? 1 : version;
    }

    function _isPostDeathUnlocked(uint256 vaultId) internal view returns (bool) {
        VaultReleaseState storage state = _vaultReleaseStates[vaultId];
        if (state.inactivityPeriod == 0) {
            return false;
        }
        return block.timestamp >= state.lastProofOfLife + state.inactivityPeriod;
    }

    function _isReleaseConditionSatisfied(uint256 documentId) internal view returns (bool) {
        uint256 vaultId = documents[documentId].vaultId;
        ReleaseCondition condition = documentReleaseCondition[documentId];

        if (condition == ReleaseCondition.ANYTIME) {
            return true;
        }

        bool postDeathUnlocked = _isPostDeathUnlocked(vaultId);

        if (condition == ReleaseCondition.LIVE_ONLY) {
            return !postDeathUnlocked;
        }

        if (condition == ReleaseCondition.EMERGENCY_ONLY) {
            return _vaultReleaseStates[vaultId].emergencyMode || postDeathUnlocked;
        }

        if (condition == ReleaseCondition.POST_DEATH_ONLY) {
            return postDeathUnlocked;
        }

        return false;
    }

    function _ownsVaultToken(address user, uint256 vaultId) internal view returns (bool) {
        return _ownedVaultTokenBalance[user][vaultId] > 0;
    }

    function _isTokenOwnerOrApproved(address owner, address spender, uint256 tokenId) internal view returns (bool) {
        return (
            spender == owner ||
            getApproved(tokenId) == spender ||
            isApprovedForAll(owner, spender)
        );
    }
}
