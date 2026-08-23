// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../libs/Ed25519.sol";

/// @dev Test-only harness that exposes the internal {Ed25519} library
///      functions so they can be exercised directly against known vectors.
contract TestEd25519 {
    function sha512(bytes calldata data) external pure returns (bytes memory) {
        return Ed25519.sha512(data);
    }

    function verify(
        bytes calldata signature,
        bytes calldata publicKey,
        bytes calldata message
    ) external pure returns (bool) {
        return Ed25519.verify(signature, publicKey, message);
    }
}
