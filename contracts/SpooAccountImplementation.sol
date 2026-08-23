// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/token/ERC1155/utils/ERC1155Holder.sol";

/**
 * @dev Minimal interface for reading TBA context from {ERC6551Registry}.
 */
interface IERC6551RegistryContext {
    function accountContext(address tbaAddress)
        external
        view
        returns (
            uint256 chainId,
            address tokenContract,
            uint256 tokenId,
            uint256 salt
        );
}

/**
 * @title SpooAccountImplementation
 * @dev ERC-6551 Token Bound Account (TBA) logic contract for SpooVault NFTs.
 *
 *      Each SpooVault Access Token (SPVT) NFT deployed through {SpooVault} can
 *      be bound to its own smart-contract wallet via {ERC6551Registry}.  This
 *      contract acts as the *implementation* that every minimal ERC-1167 proxy
 *      delegates to.
 *
 *      Context resolution
 *      ──────────────────
 *      The bound NFT triple (chainId, tokenContract, tokenId) is stored in the
 *      registry at deployment time and retrieved via `accountContext(address(this))`.
 *      The registry address is passed once at construction and stored in an
 *      immutable so it is baked into every proxy's delegatecall targets.
 *
 *      Capabilities
 *      ────────────
 *      • executeCall  — the NFT owner forwards arbitrary contract calls from
 *        the TBA address (e.g. approve document access, transfer sub-tokens).
 *      • Receive ETH & tokens — the TBA natively holds ETH, ERC-721, ERC-1155.
 *      • state()  — monotonically-increasing nonce; increments per execution.
 *      • token()  — returns (chainId, tokenContract, tokenId) of the bound NFT.
 *      • owner()  — live ERC-721 owner query; updates instantly on transfer.
 *
 *      Security model
 *      ──────────────
 *      Only the current ERC-721 owner of the bound NFT may call `executeCall`.
 *      A simple boolean re-entrancy guard prevents nested calls.
 */
contract SpooAccountImplementation is ERC721Holder, ERC1155Holder {

    // ─── Immutables ───────────────────────────────────────────────────────────

    /// @notice The ERC6551Registry that deployed (and tracks context for) this TBA.
    address public immutable registry;

    // ─── Events ───────────────────────────────────────────────────────────────

    /// @notice Emitted when the TBA forwards a call.
    event Executed(
        address indexed target,
        uint256 value,
        bytes data,
        bytes result
    );

    // ─── Errors ───────────────────────────────────────────────────────────────

    error NotTokenOwner();
    error ExecutionFailed();
    error Reentrancy();

    // ─── State ────────────────────────────────────────────────────────────────

    /// @dev Monotonically-increasing nonce incremented on every successful execution.
    uint256 public state;

    /// @dev Simple re-entrancy guard flag.
    bool private _locked;

    // ─── Constructor ─────────────────────────────────────────────────────────

    /**
     * @param _registry Address of the {ERC6551Registry} that stores TBA context.
     */
    constructor(address _registry) {
        registry = _registry;
    }

    // ─── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyOwner() {
        if (msg.sender != owner()) revert NotTokenOwner();
        _;
    }

    modifier nonReentrant() {
        if (_locked) revert Reentrancy();
        _locked = true;
        _;
        _locked = false;
    }

    // ─── Receive ETH ─────────────────────────────────────────────────────────

    receive() external payable {}

    // ─── Core: executeCall ────────────────────────────────────────────────────

    /**
     * @notice Executes an arbitrary call from the TBA address.
     * @dev Only the current owner of the bound NFT may call this function.
     *      The `state` nonce is incremented on every successful execution so
     *      clients can detect replays after NFT transfer.
     * @param target  Contract or EOA to call.
     * @param value   ETH value (wei) to forward.
     * @param data    ABI-encoded call data.
     * @return result The raw bytes returned by the callee.
     */
    function executeCall(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable onlyOwner nonReentrant returns (bytes memory result) {
        state++;
        bool success;
        (success, result) = target.call{value: value}(data);
        if (!success) {
            // Bubble up the revert reason if available.
            if (result.length > 0) {
                assembly {
                    revert(add(result, 0x20), mload(result))
                }
            }
            revert ExecutionFailed();
        }
        emit Executed(target, value, data, result);
    }

    // ─── ERC-6551: token & owner ──────────────────────────────────────────────

    /**
     * @notice Returns the bound NFT's identifying triple.
     * @dev Calls `accountContext(address(this))` on the {ERC6551Registry} to
     *      retrieve the (chainId, tokenContract, tokenId) stored at deployment.
     *      When executed via delegatecall from the proxy, `address(this)` resolves
     *      to the proxy address, giving the correct per-NFT context.
     * @return chainId       Chain ID the NFT belongs to.
     * @return tokenContract ERC-721 contract address.
     * @return tokenId       Token ID.
     */
    function token()
        public
        view
        returns (
            uint256 chainId,
            address tokenContract,
            uint256 tokenId
        )
    {
        uint256 _salt;
        (chainId, tokenContract, tokenId, _salt) = IERC6551RegistryContext(registry)
            .accountContext(address(this));
    }

    /**
     * @notice Returns the current owner of the bound NFT.
     * @dev Queries `ownerOf` on the ERC-721 token contract live so ownership
     *      changes are reflected immediately without any local state update.
     * @return The address that owns the bound NFT.
     */
    function owner() public view returns (address) {
        (, address tokenContract, uint256 tokenId) = token();
        return IERC721(tokenContract).ownerOf(tokenId);
    }

    // ─── ERC-165 ──────────────────────────────────────────────────────────────

    /**
     * @dev Reports support for ERC-165, ERC-721 token-receiver, and
     *      ERC-1155 token-receiver interfaces.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC1155Holder)
        returns (bool)
    {
        return
            interfaceId == type(IERC165).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
