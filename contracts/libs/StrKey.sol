// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title StrKey
 * @notice Decodes Stellar StrKey strings (RFC 4648 base32 without padding,
 *         version byte, CRC-16/XModem checksum) into raw key bytes.
 * @dev Only Ed25519 public key addresses ("G...", version byte 6 << 3) are
 *      supported. This lets the registry cryptographically bind the stored
 *      Stellar address string to the Ed25519 public key committed by the
 *      dual-signed payload.
 */
library StrKey {
    error InvalidStrKey();

    uint8 internal constant ED25519_PUBKEY_VERSION = 6 << 3; // 0x30
    uint16 internal constant CRC16_POLY = 0x1021;

    /// @notice Decodes a "G..." StrKey into its 32-byte Ed25519 public key.
    function decodeEd25519PublicKey(string memory strkey) internal pure returns (bytes32) {
        bytes memory data = bytes(strkey);
        if (data.length != 56) revert InvalidStrKey();

        // base32 (RFC 4648, no padding): 56 chars * 5 bits = 35 bytes
        uint8[35] memory decoded;
        uint256 buffer = 0;
        uint256 bitsLeft = 0;
        uint256 outIdx = 0;
        for (uint256 i = 0; i < data.length; i++) {
            uint256 c = uint8(data[i]);
            uint256 val;
            if (c >= 0x41 && c <= 0x5a) {
                val = c - 0x41; // 'A' - 'Z'
            } else if (c >= 0x32 && c <= 0x37) {
                val = c - 0x32 + 26; // '2' - '7'
            } else {
                revert InvalidStrKey();
            }
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                bitsLeft -= 8;
                decoded[outIdx++] = uint8((buffer >> bitsLeft) & 0xff);
                // Keep only the unconsumed bits so the rolling buffer never
                // exceeds a handful of bits (no 256-bit overflow).
                buffer &= (1 << bitsLeft) - 1;
            }
        }

        if (decoded[0] != ED25519_PUBKEY_VERSION) revert InvalidStrKey();

        // Verify the CRC-16/XModem checksum over the version byte + payload.
        // Stellar appends the checksum low-byte-first (crc & 0xff, crc >> 8).
        uint16 crc = _crc16(decoded, 33);
        uint16 expected = (uint16(decoded[34]) << 8) | uint16(decoded[33]);
        if (crc != expected) revert InvalidStrKey();

        bytes32 pubkey;
        for (uint256 i = 0; i < 32; i++) {
            pubkey |= bytes32(uint256(decoded[1 + i]) << (8 * (31 - i)));
        }
        return pubkey;
    }

    /// @dev CRC-16/XModem over the first `len` bytes of `data`.
    function _crc16(uint8[35] memory data, uint256 len) private pure returns (uint16 crc) {
        crc = 0;
        for (uint256 i = 0; i < len; i++) {
            crc ^= uint16(data[i]) << 8;
            for (uint256 j = 0; j < 8; j++) {
                if (crc & 0x8000 != 0) {
                    crc = (crc << 1) ^ CRC16_POLY;
                } else {
                    crc <<= 1;
                }
            }
        }
    }
}
