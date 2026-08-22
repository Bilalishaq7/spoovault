// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IERC6551Registry
 * @dev Interface for the ERC-6551 Token Bound Account registry as specified in
 *      EIP-6551 (https://eips.ethereum.org/EIPS/eip-6551).
 *
 *      The registry is the single canonical deployment point for Token Bound
 *      Accounts (TBAs). Given an NFT (identified by its chain ID, contract
 *      address, and token ID) plus an implementation contract and a salt, it
 *      deterministically CREATE2-deploys a minimal ERC-1167 proxy and returns
 *      its address. The same inputs always yield the same address, so callers
 *      can compute a TBA address off-chain without deploying it first.
 */
interface IERC6551Registry {
    /**
     * @dev Emitted whenever a new Token Bound Account is created.
     * @param account      The address of the newly created TBA proxy.
     * @param implementation The logic contract the proxy delegates to.
     * @param chainId      Chain ID the NFT lives on.
     * @param tokenContract ERC-721 contract address of the NFT.
     * @param tokenId      Token ID of the NFT.
     * @param salt         Caller-supplied salt for CREATE2.
     */
    event ERC6551AccountCreated(
        address indexed account,
        address indexed implementation,
        uint256 chainId,
        address indexed tokenContract,
        uint256 tokenId,
        uint256 salt
    );

    /**
     * @notice Creates a Token Bound Account for the given NFT.
     * @dev Deploys an ERC-1167 minimal proxy pointing to `implementation` via
     *      CREATE2.  The call is idempotent: if the account already exists the
     *      existing address is returned and no event is emitted.
     * @param implementation Address of the TBA logic contract.
     * @param chainId        Chain ID of the NFT's home chain.
     * @param tokenContract  ERC-721 contract that minted the NFT.
     * @param tokenId        Token ID of the NFT.
     * @param salt           Caller-supplied entropy for CREATE2 uniqueness.
     * @param initData       Optional initialisation call forwarded to the new
     *                       account immediately after deployment.
     * @return account       The (possibly pre-existing) TBA address.
     */
    function createAccount(
        address implementation,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId,
        uint256 salt,
        bytes calldata initData
    ) external returns (address account);

    /**
     * @notice Computes the deterministic TBA address without deploying it.
     * @param implementation Address of the TBA logic contract.
     * @param chainId        Chain ID of the NFT's home chain.
     * @param tokenContract  ERC-721 contract that minted the NFT.
     * @param tokenId        Token ID of the NFT.
     * @param salt           Caller-supplied entropy for CREATE2.
     * @return account       The pre-computed TBA address.
     */
    function account(
        address implementation,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId,
        uint256 salt
    ) external view returns (address account);
}
