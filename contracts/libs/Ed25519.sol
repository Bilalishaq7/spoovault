// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title Ed25519
 * @notice Compact, dependency-free Ed25519 signature verification in Solidity.
 * @dev Implements the verification algorithm from RFC 8032 (Ed25519) using
 *      native EVM `addmod`/`mulmod` opcodes for field arithmetic over the
 *      prime p = 2^255 - 19 and a self-contained SHA-512 implementation.
 *
 *      The library performs the strict (cofactorless) check
 *          [S]B == R + [k]A
 *      with k = SHA-512(R || A || M) reduced modulo the group order L, and
 *      additionally requires S < L and that both A and R decode to valid
 *      curve points, so malformed or non-canonical signatures are rejected.
 */
library Ed25519 {
    // Field prime p = 2^255 - 19
    uint256 internal constant P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
    // Curve constant d = -121665/121666 mod p
    uint256 internal constant D = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3;
    // 2d mod p
    uint256 internal constant D2 = 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159;
    // Group order L
    uint256 internal constant L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;
    // 2^256 mod L (used to reduce the 512-bit SHA-512 scalar below L)
    uint256 internal constant R_256 = 0x0ffffffffffffffffffffffffffffffec6ef5bf4737dcf70d6ec31748d98951d;
    // sqrt(-1) mod p
    uint256 internal constant SQRT_M1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0;
    // Low 255-bit mask used to strip the sign bit off a compressed point
    uint256 internal constant MASK_255 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    // Base point B
    uint256 internal constant BX = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a;
    uint256 internal constant BY = 0x6666666666666666666666666666666666666666666666666666666666666658;

    // Extended homogeneous coordinates (X, Y, Z, T) with T = X*Y/Z
    struct Point {
        uint256 x;
        uint256 y;
        uint256 z;
        uint256 t;
    }

    /**
     * @notice Verifies an Ed25519 signature over `message`.
     * @param signature 64-byte signature (R || S), both little-endian.
     * @param publicKey 32-byte compressed Ed25519 public key.
     * @param message The signed message bytes.
     * @return true when the signature is cryptographically valid.
     */
    function verify(
        bytes memory signature,
        bytes memory publicKey,
        bytes memory message
    ) internal pure returns (bool) {
        if (signature.length != 64 || publicKey.length != 32) return false;

        (Point memory r, bool okR) = decompress(_slice(signature, 0, 32));
        if (!okR) return false;

        uint256 s = decodeLittleEndian(signature, 32);
        if (s >= L) return false;

        (Point memory a, bool okA) = decompress(publicKey);
        if (!okA) return false;

        // k = SHA-512(R || A || M) interpreted as a little-endian integer mod L
        bytes memory hashInput = abi.encodePacked(_slice(signature, 0, 32), publicKey, message);
        uint256 k = digestModL(sha512(hashInput));

        Point memory base = Point(BX, BY, 1, mulmod(BX, BY, P));
        Point memory lhs = scalarMult(base, s);
        Point memory rhs = addPoint(r, scalarMult(a, k));

        return pointsEqual(lhs, rhs);
    }

    // ------------------------------------------------------------------
    // SHA-512 (FIPS 180-4)
    // ------------------------------------------------------------------

    /**
     * @notice Computes the SHA-512 digest of `data`.
     * @return 64-byte digest.
     */
    function sha512(bytes memory data) internal pure returns (bytes memory) {
        uint64[8] memory h = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179
        ];

        // Padding: 0x80, zeros, then the 128-bit big-endian bit length.
        uint256 len = data.length;
        uint256 paddedLen = ((len + 136) / 128) * 128; // ceil((len + 9) / 128) * 128
        bytes memory padded = new bytes(paddedLen);
        for (uint256 i = 0; i < len; i++) {
            padded[i] = data[i];
        }
        padded[len] = 0x80;
        uint256 bitLen = len * 8;
        for (uint256 i = 0; i < 8; i++) {
            padded[paddedLen - 1 - i] = bytes1(uint8(bitLen >> (8 * i)));
        }

        uint64[80] memory k = [
            0x428a2f98d728ae22,
            0x7137449123ef65cd,
            0xb5c0fbcfec4d3b2f,
            0xe9b5dba58189dbbc,
            0x3956c25bf348b538,
            0x59f111f1b605d019,
            0x923f82a4af194f9b,
            0xab1c5ed5da6d8118,
            0xd807aa98a3030242,
            0x12835b0145706fbe,
            0x243185be4ee4b28c,
            0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f,
            0x80deb1fe3b1696b1,
            0x9bdc06a725c71235,
            0xc19bf174cf692694,
            0xe49b69c19ef14ad2,
            0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5,
            0x240ca1cc77ac9c65,
            0x2de92c6f592b0275,
            0x4a7484aa6ea6e483,
            0x5cb0a9dcbd41fbd4,
            0x76f988da831153b5,
            0x983e5152ee66dfab,
            0xa831c66d2db43210,
            0xb00327c898fb213f,
            0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2,
            0xd5a79147930aa725,
            0x06ca6351e003826f,
            0x142929670a0e6e70,
            0x27b70a8546d22ffc,
            0x2e1b21385c26c926,
            0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df,
            0x650a73548baf63de,
            0x766a0abb3c77b2a8,
            0x81c2c92e47edaee6,
            0x92722c851482353b,
            0xa2bfe8a14cf10364,
            0xa81a664bbc423001,
            0xc24b8b70d0f89791,
            0xc76c51a30654be30,
            0xd192e819d6ef5218,
            0xd69906245565a910,
            0xf40e35855771202a,
            0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8,
            0x1e376c085141ab53,
            0x2748774cdf8eeb99,
            0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63,
            0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc,
            0x78a5636f43172f60,
            0x84c87814a1f0ab72,
            0x8cc702081a6439ec,
            0x90befffa23631e28,
            0xa4506cebde82bde9,
            0xbef9a3f7b2c67915,
            0xc67178f2e372532b,
            0xca273eceea26619c,
            0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e,
            0xf57d4f7fee6ed178,
            0x06f067aa72176fba,
            0x0a637dc5a2c898a6,
            0x113f9804bef90dae,
            0x1b710b35131c471b,
            0x28db77f523047d84,
            0x32caab7b40c72493,
            0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6,
            0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec,
            0x6c44198c4a475817
        ];

        for (uint256 blockStart = 0; blockStart < paddedLen; blockStart += 128) {
            uint64[80] memory w;
            for (uint256 i = 0; i < 16; i++) {
                uint256 idx = blockStart + i * 8;
                w[i] = (uint64(uint8(padded[idx])) << 56) |
                    (uint64(uint8(padded[idx + 1])) << 48) |
                    (uint64(uint8(padded[idx + 2])) << 40) |
                    (uint64(uint8(padded[idx + 3])) << 32) |
                    (uint64(uint8(padded[idx + 4])) << 24) |
                    (uint64(uint8(padded[idx + 5])) << 16) |
                    (uint64(uint8(padded[idx + 6])) << 8) |
                    uint64(uint8(padded[idx + 7]));
            }
            for (uint256 i = 16; i < 80; i++) {
                unchecked {
                    w[i] = w[i - 16] + _sigma0(w[i - 15]) + w[i - 7] + _sigma1(w[i - 2]);
                }
            }

            // Working state lives in a memory array so the 80-round loop keeps
            // its stack footprint small enough for the viaIR code generator.
            uint64[8] memory st;
            st[0] = h[0];
            st[1] = h[1];
            st[2] = h[2];
            st[3] = h[3];
            st[4] = h[4];
            st[5] = h[5];
            st[6] = h[6];
            st[7] = h[7];

            for (uint256 i = 0; i < 80; i++) {
                unchecked {
                    uint64 temp1 = st[7] +
                        (rotr64(st[4], 14) ^ rotr64(st[4], 18) ^ rotr64(st[4], 41)) +
                        ((st[4] & st[5]) ^ ((~st[4]) & st[6])) +
                        k[i] +
                        w[i];
                    uint64 temp2 =
                        (rotr64(st[0], 28) ^ rotr64(st[0], 34) ^ rotr64(st[0], 39)) +
                        ((st[0] & st[1]) ^ (st[0] & st[2]) ^ (st[1] & st[2]));
                    st[7] = st[6];
                    st[6] = st[5];
                    st[5] = st[4];
                    st[4] = st[3] + temp1;
                    st[3] = st[2];
                    st[2] = st[1];
                    st[1] = st[0];
                    st[0] = temp1 + temp2;
                }
            }

            unchecked {
                h[0] += st[0];
                h[1] += st[1];
                h[2] += st[2];
                h[3] += st[3];
                h[4] += st[4];
                h[5] += st[5];
                h[6] += st[6];
                h[7] += st[7];
            }
        }

        bytes memory out = new bytes(64);
        for (uint256 i = 0; i < 8; i++) {
            uint64 word = h[i];
            for (uint256 j = 0; j < 8; j++) {
                out[i * 8 + j] = bytes1(uint8(word >> (8 * (7 - j))));
            }
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Field arithmetic mod p = 2^255 - 19
    // ------------------------------------------------------------------

    function fadd(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, b, P);
    }

    function fsub(uint256 a, uint256 b) internal pure returns (uint256) {
        return addmod(a, P - b, P);
    }

    function fmul(uint256 a, uint256 b) internal pure returns (uint256) {
        return mulmod(a, b, P);
    }

    function fexp(uint256 base, uint256 exponent) internal pure returns (uint256 result) {
        result = 1;
        while (exponent > 0) {
            if (exponent & 1 == 1) {
                result = mulmod(result, base, P);
            }
            base = mulmod(base, base, P);
            exponent >>= 1;
        }
    }

    /// @notice Modular inverse via Fermat's little theorem: a^(p-2) mod p.
    function finv(uint256 a) internal pure returns (uint256) {
        return fexp(a, P - 2);
    }

    /// @notice Square root mod p for p = 5 (mod 8); the caller must confirm
    ///         that the returned value actually squares back to `x`.
    function fsqrt(uint256 x) internal pure returns (uint256) {
        uint256 r = fexp(x, (P + 3) / 8);
        if (mulmod(r, r, P) != x) {
            r = mulmod(r, SQRT_M1, P);
        }
        return r;
    }

    // ------------------------------------------------------------------
    // Twisted Edwards curve operations (a = -1, extended coordinates)
    // ------------------------------------------------------------------

    function addPoint(Point memory p1, Point memory p2) internal pure returns (Point memory) {
        uint256 aa = fmul(fsub(p1.y, p1.x), fsub(p2.y, p2.x));
        uint256 bb = fmul(fadd(p1.y, p1.x), fadd(p2.y, p2.x));
        uint256 cc = fmul(fmul(p1.t, p2.t), D2);
        uint256 dd = fmul(fmul(p1.z, p2.z), 2);
        uint256 e = fsub(bb, aa);
        uint256 f = fsub(dd, cc);
        uint256 g = fadd(dd, cc);
        uint256 h = fadd(bb, aa);
        return Point(fmul(e, f), fmul(g, h), fmul(f, g), fmul(e, h));
    }

    function doublePoint(Point memory p) internal pure returns (Point memory) {
        uint256 aa = fmul(p.x, p.x);
        uint256 bb = fmul(p.y, p.y);
        uint256 cc = fmul(fmul(p.z, p.z), 2);
        uint256 dd = fsub(0, aa); // -A (curve coefficient a = -1)
        uint256 e = fsub(fsub(fmul(fadd(p.x, p.y), fadd(p.x, p.y)), aa), bb); // (x+y)^2 - A - B
        uint256 g = fadd(dd, bb);
        uint256 f = fsub(g, cc);
        uint256 h = fsub(dd, bb);
        return Point(fmul(e, f), fmul(g, h), fmul(f, g), fmul(e, h));
    }

    function scalarMult(Point memory p, uint256 k) internal pure returns (Point memory result) {
        // Identity point in extended coordinates: (0, 1, 1, 0)
        result = Point(0, 1, 1, 0);
        while (k > 0) {
            if (k & 1 == 1) {
                result = addPoint(result, p);
            }
            p = doublePoint(p);
            k >>= 1;
        }
    }

    function pointsEqual(Point memory p1, Point memory p2) internal pure returns (bool) {
        return fmul(p1.x, p2.z) == fmul(p2.x, p1.z) && fmul(p1.y, p2.z) == fmul(p2.y, p1.z);
    }

    /// @notice Decompresses a 32-byte Edwards point (little-endian y with a
    ///         sign bit in the top bit of the last byte).
    function decompress(bytes memory encoded) internal pure returns (Point memory p, bool ok) {
        if (encoded.length != 32) return (p, false);
        uint256 sign = uint256(uint8(encoded[31])) >> 7;
        uint256 y = decodeLittleEndian(encoded, 0) & MASK_255;
        if (y >= P) return (p, false);

        uint256 y2 = mulmod(y, y, P);
        uint256 u = fsub(y2, 1); // y^2 - 1
        uint256 v = fadd(mulmod(D, y2, P), 1); // d*y^2 + 1
        uint256 x2 = fmul(u, finv(v)); // (y^2 - 1) / (d*y^2 + 1)
        uint256 x = fsqrt(x2);
        if (mulmod(x, x, P) != x2) return (p, false);

        if ((x & 1) != sign) {
            x = fsub(0, x);
        }
        if (x == 0 && sign == 1) return (p, false);

        p = Point(x, y, 1, mulmod(x, y, P));
        return (p, true);
    }

    /// @notice Reduces a 64-byte little-endian digest modulo the group order L.
    function digestModL(bytes memory digest) internal pure returns (uint256) {
        uint256 lo = decodeLittleEndian(digest, 0);
        uint256 hi = decodeLittleEndian(digest, 32);
        return addmod(lo % L, mulmod(hi, R_256, L), L);
    }

    // ------------------------------------------------------------------
    // Byte helpers
    // ------------------------------------------------------------------

    function decodeLittleEndian(bytes memory data, uint256 offset) internal pure returns (uint256 v) {
        for (uint256 i = 0; i < 32; i++) {
            v |= uint256(uint8(data[offset + i])) << (8 * i);
        }
    }

    function _slice(
        bytes memory data,
        uint256 start,
        uint256 length
    ) internal pure returns (bytes memory out) {
        out = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            out[i] = data[start + i];
        }
    }

    function rotr64(uint64 x, uint256 n) internal pure returns (uint64) {
        return uint64((uint256(x) >> n) | (uint256(x) << (64 - n)));
    }

    function _sigma0(uint64 x) internal pure returns (uint64) {
        return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7);
    }

    function _sigma1(uint64 x) internal pure returns (uint64) {
        return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6);
    }
}
