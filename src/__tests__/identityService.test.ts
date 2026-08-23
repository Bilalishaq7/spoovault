import { describe, it, expect, beforeEach } from 'vitest';
import { identityService } from '../services/identity.service';

// In-memory localStorage shim for Vitest Node environment
class MockLocalStorage {
  private store: Record<string, string> = {};

  getItem(key: string): string | null {
    return this.store[key] || null;
  }

  setItem(key: string, value: string): void {
    this.store[key] = String(value);
  }

  removeItem(key: string): void {
    delete this.store[key];
  }

  clear(): void {
    this.store = {};
  }
}

if (typeof globalThis.localStorage === 'undefined') {
  (globalThis as any).localStorage = new MockLocalStorage();
}
if (typeof globalThis.window === 'undefined') {
  (globalThis as any).window = {
    localStorage: (globalThis as any).localStorage,
  };
}

describe('Cross-Chain Identity Binding Registry', () => {
  const evmAddress = '0x64128680775Ef626379DeF6E5c815AeA8F4707Ef';
  const stellarAddress = 'GBXTH2BBW2R55BN4C7NDR5HBAJLVV7PZZNPGPFFQG2K42N6NFDY2L5WW';

  beforeEach(() => {
    identityService.clear();
  });

  describe('Address Format Validation', () => {
    it('should correctly identify valid EVM addresses', () => {
      expect(identityService.isValidEVMAddress(evmAddress)).toBe(true);
      expect(identityService.isValidEVMAddress('0x0000000000000000000000000000000000000000')).toBe(true);
      expect(identityService.isValidEVMAddress('InvalidAddress')).toBe(false);
      expect(identityService.isValidEVMAddress(stellarAddress)).toBe(false);
    });

    it('should correctly identify valid Stellar public keys', () => {
      expect(identityService.isValidStellarAddress(stellarAddress)).toBe(true);
      expect(identityService.isValidStellarAddress(evmAddress)).toBe(false);
      expect(identityService.isValidStellarAddress('GBadLength')).toBe(false);
    });

    it('should validate multi-chain address formats', () => {
      expect(identityService.isValidMultiChainAddress(evmAddress)).toBe(true);
      expect(identityService.isValidMultiChainAddress(stellarAddress)).toBe(true);
      expect(identityService.isValidMultiChainAddress('NotAnAddress')).toBe(false);
    });
  });

  describe('Identity Registration & Resolution', () => {
    it('should register linked EVM and Stellar public keys', async () => {
      const binding = await identityService.registerIdentity(evmAddress, stellarAddress);
      expect(binding.evmAddress).toBe(evmAddress);
      expect(binding.stellarAddress).toBe(stellarAddress);

      const registeredList = identityService.getRegisteredIdentities();
      expect(registeredList.length).toBe(1);
    });

    it('should resolve linked Stellar address from EVM input', async () => {
      await identityService.registerIdentity(evmAddress, stellarAddress);

      const resolved = await identityService.resolveStellarAddress(evmAddress);
      expect(resolved).toBe(stellarAddress);
    });

    it('should resolve linked EVM address from Stellar input', async () => {
      await identityService.registerIdentity(evmAddress, stellarAddress);

      const resolved = await identityService.resolveEVMAddress(stellarAddress);
      expect(resolved).toBe(evmAddress);
    });

    it('should return input directly if already in target format', async () => {
      expect(await identityService.resolveStellarAddress(stellarAddress)).toBe(stellarAddress);
      expect(await identityService.resolveEVMAddress(evmAddress)).toBe(evmAddress);
    });
  });

  describe('Conflict & Invalid Parameter Handling', () => {
    it('should reject identity registration with malformed EVM address', async () => {
      await expect(
        identityService.registerIdentity('0xBadEVM', stellarAddress)
      ).rejects.toThrow('Invalid EVM address format');
    });

    it('should reject identity registration with malformed Stellar address', async () => {
      await expect(
        identityService.registerIdentity(evmAddress, 'GBadStellar')
      ).rejects.toThrow('Invalid Stellar address format');
    });

    it('should reject conflicting EVM re-registration to a different Stellar address', async () => {
      await identityService.registerIdentity(evmAddress, stellarAddress);
      const otherStellar = 'GAY2L262272W72722222222222222222222222222222222222222222';

      await expect(
        identityService.registerIdentity(evmAddress, otherStellar)
      ).rejects.toThrow('already linked to a different Stellar address');
    });

    it('should reject conflicting Stellar re-registration to a different EVM address', async () => {
      await identityService.registerIdentity(evmAddress, stellarAddress);
      const otherEvm = '0x1111111111111111111111111111111111111111';

      await expect(
        identityService.registerIdentity(otherEvm, stellarAddress)
      ).rejects.toThrow('already linked to a different EVM address');
    });
  });

  describe('Cross-Network Automatic Resolution', () => {
    it('should resolve EVM input to Stellar format on Stellar network target', async () => {
      await identityService.registerIdentity(evmAddress, stellarAddress);

      const resolved = await identityService.resolveAddressForNetwork(evmAddress, 'stellar');
      expect(resolved).toBe(stellarAddress);
    });

    it('should resolve Stellar input to EVM format on Avalanche network target', async () => {
      await identityService.registerIdentity(evmAddress, stellarAddress);

      const resolved = await identityService.resolveAddressForNetwork(stellarAddress, 'avalanche');
      expect(resolved).toBe(evmAddress);
    });

    it('should throw clear informative error when cross-network address is unregistered', async () => {
      const unregisteredEvm = '0x9999999999999999999999999999999999999999';

      await expect(
        identityService.resolveAddressForNetwork(unregisteredEvm, 'stellar')
      ).rejects.toThrow('is not registered to a linked Stellar identity');
    });
  });
});
