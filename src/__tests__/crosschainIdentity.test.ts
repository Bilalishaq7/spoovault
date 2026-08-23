import { describe, it, expect } from 'vitest';
import { ethers } from 'ethers';
import nacl from 'tweetnacl';
import { StrKey } from '@stellar/stellar-sdk';
import { stellarService } from '../services/stellar.service';

const BIND_PREFIX = '0x42696e644964656e74697479'; // "BindIdentity" (12 bytes)

const toHex = (bytes: Uint8Array): string =>
  '0x' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const encodeStellar = (publicKey: Uint8Array): string =>
  StrKey.encodeEd25519PublicKey(Buffer.from(publicKey));

describe('stellarService - Cross-Chain Identity Binding (dual-signed)', () => {
  it('builds a deterministic binding message hash', async () => {
    const keyPair = nacl.sign.keyPair();
    const stellarAddress = encodeStellar(keyPair.publicKey);
    const wallet = ethers.Wallet.createRandom();
    const timestamp = 1700000000;

    const hash = await stellarService.buildIdentityBindingMessageHash(
      wallet.address,
      stellarAddress,
      timestamp
    );

    // Reference computation: payload = "BindIdentity" || evm(20) || pk(32) || ts(8 BE)
    const payload = ethers.concat([
      ethers.toUtf8Bytes('BindIdentity'),
      wallet.address,
      keyPair.publicKey,
      ethers.toBeHex(timestamp, 8),
    ]);
    expect(hash).toBe(ethers.keccak256(payload));
  });

  it('builds the same message hash as the EVM registry payload', async () => {
    const keyPair = nacl.sign.keyPair();
    const stellarAddress = encodeStellar(keyPair.publicKey);
    const wallet = ethers.Wallet.createRandom();
    const timestamp = 1700000000;

    const hash = await stellarService.buildIdentityBindingMessageHash(
      wallet.address,
      stellarAddress,
      timestamp
    );

    // Mirrors the CrossChainIdentityRegistry.sol on-chain computation
    const expected = ethers.solidityPackedKeccak256(
      ['bytes12', 'address', 'bytes32', 'uint64'],
      [BIND_PREFIX, wallet.address, toHex(keyPair.publicKey), timestamp]
    );
    expect(hash).toBe(expected);
  });

  it('binds a dual-signed identity and resolves it in both directions', async () => {
    const keyPair = nacl.sign.keyPair();
    const stellarAddress = encodeStellar(keyPair.publicKey);
    const wallet = ethers.Wallet.createRandom();
    const timestamp = Math.floor(Date.now() / 1000);

    const messageHash = await stellarService.buildIdentityBindingMessageHash(
      wallet.address,
      stellarAddress,
      timestamp
    );
    const evmSignature = await wallet.signMessage(ethers.getBytes(messageHash));
    const stellarSignature = toHex(
      nacl.sign.detached(ethers.getBytes(messageHash), keyPair.secretKey)
    );
    const stellarPublicKey = toHex(keyPair.publicKey);

    await stellarService.bindIdentity({
      evmAddress: wallet.address,
      stellarAddress,
      stellarPublicKey,
      timestamp,
      evmSignature,
      stellarSignature,
    });

    expect(await stellarService.resolveEvmToStellar(wallet.address)).toBe(stellarAddress);
    expect(await stellarService.resolveStellarToEvm(stellarAddress)).toBe(
      wallet.address.toLowerCase()
    );
    expect(await stellarService.resolveEvmToPublicKey(wallet.address)).toBe(stellarPublicKey);
  });

  it('rejects a binding with an invalid EVM signature (wrong signer)', async () => {
    const keyPair = nacl.sign.keyPair();
    const stellarAddress = encodeStellar(keyPair.publicKey);
    const wallet = ethers.Wallet.createRandom();
    const other = ethers.Wallet.createRandom();
    const timestamp = Math.floor(Date.now() / 1000);

    const messageHash = await stellarService.buildIdentityBindingMessageHash(
      wallet.address,
      stellarAddress,
      timestamp
    );
    // Signed by a different wallet than the one being bound
    const evmSignature = await other.signMessage(ethers.getBytes(messageHash));
    const stellarSignature = toHex(
      nacl.sign.detached(ethers.getBytes(messageHash), keyPair.secretKey)
    );

    await expect(
      stellarService.bindIdentity({
        evmAddress: wallet.address,
        stellarAddress,
        stellarPublicKey: toHex(keyPair.publicKey),
        timestamp,
        evmSignature,
        stellarSignature,
      })
    ).rejects.toThrow(/EVM signature/);
  });

  it('rejects a binding with an invalid Stellar signature', async () => {
    const keyPair = nacl.sign.keyPair();
    const stellarAddress = encodeStellar(keyPair.publicKey);
    const wallet = ethers.Wallet.createRandom();
    const timestamp = Math.floor(Date.now() / 1000);

    const messageHash = await stellarService.buildIdentityBindingMessageHash(
      wallet.address,
      stellarAddress,
      timestamp
    );
    const evmSignature = await wallet.signMessage(ethers.getBytes(messageHash));

    await expect(
      stellarService.bindIdentity({
        evmAddress: wallet.address,
        stellarAddress,
        stellarPublicKey: toHex(keyPair.publicKey),
        timestamp,
        evmSignature,
        stellarSignature: '0x' + '00'.repeat(64), // garbage
      })
    ).rejects.toThrow(/Stellar signature/);
  });

  it('rejects a single-signed binding (missing Stellar signature)', async () => {
    const keyPair = nacl.sign.keyPair();
    const stellarAddress = encodeStellar(keyPair.publicKey);
    const wallet = ethers.Wallet.createRandom();
    const timestamp = Math.floor(Date.now() / 1000);

    const messageHash = await stellarService.buildIdentityBindingMessageHash(
      wallet.address,
      stellarAddress,
      timestamp
    );
    const evmSignature = await wallet.signMessage(ethers.getBytes(messageHash));

    await expect(
      stellarService.bindIdentity({
        evmAddress: wallet.address,
        stellarAddress,
        stellarPublicKey: toHex(keyPair.publicKey),
        timestamp,
        evmSignature,
        stellarSignature: '',
      })
    ).rejects.toThrow(/Both EVM and Stellar signatures are required/);
  });

  it('rejects a single-signed binding (missing EVM signature)', async () => {
    const keyPair = nacl.sign.keyPair();
    const stellarAddress = encodeStellar(keyPair.publicKey);
    const wallet = ethers.Wallet.createRandom();
    const timestamp = Math.floor(Date.now() / 1000);

    const messageHash = await stellarService.buildIdentityBindingMessageHash(
      wallet.address,
      stellarAddress,
      timestamp
    );
    const stellarSignature = toHex(
      nacl.sign.detached(ethers.getBytes(messageHash), keyPair.secretKey)
    );

    await expect(
      stellarService.bindIdentity({
        evmAddress: wallet.address,
        stellarAddress,
        stellarPublicKey: toHex(keyPair.publicKey),
        timestamp,
        evmSignature: '',
        stellarSignature,
      })
    ).rejects.toThrow(/Both EVM and Stellar signatures are required/);
  });

  it('signs the binding message with a MetaMask-compatible signer', async () => {
    const wallet = ethers.Wallet.createRandom();
    const messageHash = ethers.keccak256(ethers.toUtf8Bytes('BindIdentity-test'));

    const { signature, recoveryId } = await stellarService.signIdentityBindingWithMetaMask(
      messageHash,
      wallet
    );

    // The returned signature must recover the signing wallet
    const recovered = ethers.verifyMessage(ethers.getBytes(messageHash), signature);
    expect(recovered.toLowerCase()).toBe(wallet.address.toLowerCase());
    expect([0, 1]).toContain(recoveryId);
  });

  it('signs the binding message with Freighter signBlob', async () => {
    const keyPair = nacl.sign.keyPair();
    const messageHash = '0x' + 'ab'.repeat(32);
    const msgBytes = ethers.getBytes(messageHash);
    const expectedSig = nacl.sign.detached(msgBytes, keyPair.secretKey);

    stellarService.setMockFreighter({
      signBlob: async (blob: string) => {
        // blob is base64 of the message hash
        const decoded = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
        expect(Array.from(decoded)).toEqual(Array.from(msgBytes));
        return btoa(String.fromCharCode(...expectedSig));
      },
    });

    const signature = await stellarService.signIdentityBindingWithFreighter(messageHash);
    expect(signature).toBe(toHex(expectedSig));
  });

  it('throws when Freighter signBlob is unavailable', async () => {
    stellarService.setMockFreighter({});
    await expect(
      stellarService.signIdentityBindingWithFreighter('0x' + 'ab'.repeat(32))
    ).rejects.toThrow(/signBlob/);
  });
});
