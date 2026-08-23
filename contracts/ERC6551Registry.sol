// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IERC6551Registry.sol";

/**
 * @title ERC6551Registry
 * @dev Canonical ERC-6551 registry that deterministically CREATE2-deploys an
 *      ERC-1167 minimal proxy for each (implementation, chainId, tokenContract,
 *      tokenId, salt) tuple.
 *
 *      Follows the reference implementation described in EIP-6551:
 *      https://eips.ethereum.org/EIPS/eip-6551
 *
 *      Context storage
 *      ───────────────
 *      Instead of appending context to the proxy bytecode (which is unreliable
 *      across compiler versions), the registry stores the binding in a mapping
 *      keyed by the TBA address. The SpooAccountImplementation reads it back
 *      via a call to `accountContext(address)` on the registry address stored
 *      in an immutable slot.
 *
 *      Deployment is idempotent: calling `createAccount` a second time with
 *      the same arguments simply returns the already-deployed address without
 *      re-deploying or reverting.
 */
contract ERC6551Registry is IERC6551Registry {

    // ─── Context storage ──────────────────────────────────────────────────────

    struct AccountContext {
        uint256 chainId;
        address tokenContract;
        uint256 tokenId;
        uint256 salt;
    }

    /// @dev TBA address → binding context.
    mapping(address => AccountContext) private _contexts;

    /**
     * @notice Returns the NFT binding context for a deployed TBA.
     * @param tbaAddress The Token Bound Account address.
     */
    function accountContext(address tbaAddress)
        external
        view
        returns (
            uint256 chainId,
            address tokenContract,
            uint256 tokenId,
            uint256 salt
        )
    {
        AccountContext storage ctx = _contexts[tbaAddress];
        return (ctx.chainId, ctx.tokenContract, ctx.tokenId, ctx.salt);
    }

    // ─── IERC6551Registry ─────────────────────────────────────────────────────

    /**
     * @inheritdoc IERC6551Registry
     */
    function createAccount(
        address implementation,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId,
        uint256 salt,
        bytes calldata initData
    ) external override returns (address tbaAccount) {
        bytes memory code = _proxyCode(implementation);
        bytes32 salt32 = _deriveSalt(chainId, tokenContract, tokenId, salt);

        tbaAccount = _computeAddressFromCode(keccak256(code), salt32);

        // If already deployed return early without re-deploying.
        if (tbaAccount.code.length > 0) {
            return tbaAccount;
        }

        // CREATE2-deploy the minimal proxy.
        assembly {
            tbaAccount := create2(0, add(code, 0x20), mload(code), salt32)
        }
        require(tbaAccount != address(0), "ERC6551Registry: CREATE2 failed");

        // Persist context so the account can call back for its binding info.
        _contexts[tbaAccount] = AccountContext({
            chainId: chainId,
            tokenContract: tokenContract,
            tokenId: tokenId,
            salt: salt
        });

        emit ERC6551AccountCreated(
            tbaAccount,
            implementation,
            chainId,
            tokenContract,
            tokenId,
            salt
        );

        // Forward optional init data.
        if (initData.length > 0) {
            (bool success, ) = tbaAccount.call(initData);
            require(success, "ERC6551Registry: init call failed");
        }
    }

    /**
     * @inheritdoc IERC6551Registry
     */
    function account(
        address implementation,
        uint256 chainId,
        address tokenContract,
        uint256 tokenId,
        uint256 salt
    ) external view override returns (address) {
        bytes32 salt32 = _deriveSalt(chainId, tokenContract, tokenId, salt);
        bytes32 codeHash = keccak256(_proxyCode(implementation));
        return _computeAddressFromCode(codeHash, salt32);
    }

    // ─── Internals ────────────────────────────────────────────────────────────

    /**
     * @dev Standard ERC-1167 minimal proxy creation bytecode delegating to `implementation`.
     */
    function _proxyCode(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(
            hex"3d602d80600a3d3981f3363d3d373d3d3d363d73",
            implementation,
            hex"5af43d82803e903d91602b57fd5bf3"
        );
    }

    /**
     * @dev Derives a deterministic bytes32 salt from the full ERC-6551 context tuple
     *      so that (chainId, tokenContract, tokenId, salt) maps to a unique CREATE2 salt.
     */
    function _deriveSalt(
        uint256 chainId,
        address tokenContract,
        uint256 tokenId,
        uint256 salt
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(chainId, tokenContract, tokenId, salt));
    }

    /**
     * @dev Computes the CREATE2 address from the code hash and derived salt.
     */
    function _computeAddressFromCode(bytes32 codeHash, bytes32 salt32)
        internal
        view
        returns (address)
    {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(this),
                            salt32,
                            codeHash
                        )
                    )
                )
            )
        );
    }
}
