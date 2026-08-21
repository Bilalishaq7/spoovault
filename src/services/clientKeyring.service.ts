import {
  generateECIESKeyPairBase64,
  importECIESPublicKey,
  importECIESPrivateKey,
} from "../utils/crypto";

import { secretsService, PBKDF2_ITERATIONS } from "./secrets.service";
import {
  WebAuthnError,
  authenticatePasskey,
  decryptWithPrfKey,
  deriveAesKeyFromPrfOutput,
  encryptWithPrfKey,
  generateChallenge,
  generatePrfSalt,
  getRelyingPartyId,
  isWebAuthnAvailable,
  registerPasskey,
} from "./webauthn.service";

export interface KeyPairRecord {
  account: string;
  publicKey: string;
  encryptedPrivateKey: string;
  createdAt: number;
  updatedAt: number;
  hasPin: boolean;
  /** Whether a hardware-backed WebAuthn passkey (TouchID / FaceID / YubiKey) protects this keyring. */
  hasPasskey?: boolean;
  /** Base64url WebAuthn credential id used to re-authenticate with the hardware authenticator. */
  passkeyCredentialId?: string;
  /** Base64url PRF eval salt — public, but required (with the authenticator secret) to re-derive the key. */
  passkeyPrfSalt?: string;
  /** Private key encrypted with the AES key derived from the authenticator's PRF output. */
  passkeyEncryptedPrivateKey?: string;
}

/**
 * Options for keypair generation.
 */
export interface GenerateKeyPairOptions {
  /**
   * Attempt to register a hardware-backed WebAuthn passkey (PRF extension) during keyring
   * creation. Defaults to `true`; falls back to PIN/passphrase protection when WebAuthn is
   * unavailable, unsupported, or the user cancels.
   */
  enablePasskey?: boolean;
}

export interface KeyPairBackupPayload {
  version: "spoovault-keyring-backup-v1";
  account: string;
  publicKey: string;
  encryptedPrivateKey: string;
  exportedAt: string;
}

const DB_NAME = "spoovault-keyring";
const DB_VERSION = 1;
const STORE_NAME = "keypairs";

// In-memory session cache for unlocked private keys during the active browser session
const sessionKeyCache = new Map<string, string>();

// Fallback in-memory store for environments without IndexedDB (e.g. Node tests without mock IDB)
const memoryStore = new Map<string, KeyPairRecord>();

const isIndexedDBAvailable = (): boolean => {
  return typeof window !== "undefined" && typeof window.indexedDB !== "undefined";
};

const getEffectivePassphrase = (account: string, pinOrPassphrase?: string): { passphrase: string; isCustomPin: boolean } => {
  const trimmed = pinOrPassphrase?.trim();
  if (trimmed) {
    return { passphrase: trimmed, isCustomPin: true };
  }
  // Default account-bound deterministic derivation entropy for seamless zero-prompt mode
  const defaultSalt = `spoovault:keyring:default:${account.toLowerCase()}`;
  return { passphrase: defaultSalt, isCustomPin: false };
};

const openDatabase = (): Promise<IDBDatabase> => {
  return new Promise((resolve, reject) => {
    if (!isIndexedDBAvailable()) {
      reject(new Error("IndexedDB is not available"));
      return;
    }

    const request = window.indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "account" });
      }
    };

    request.onsuccess = () => {
      resolve(request.result);
    };

    request.onerror = () => {
      reject(request.error || new Error("Failed to open IndexedDB"));
    };
  });
};

const idbGet = async (account: string): Promise<KeyPairRecord | null> => {
  const normalized = account.toLowerCase();
  if (!isIndexedDBAvailable()) {
    return memoryStore.get(normalized) || null;
  }

  try {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const request = store.get(normalized);

      request.onsuccess = () => {
        resolve(request.result || null);
      };
      request.onerror = () => {
        reject(request.error);
      };
    });
  } catch {
    return memoryStore.get(normalized) || null;
  }
};

const idbPut = async (record: KeyPairRecord): Promise<void> => {
  const normalized = record.account.toLowerCase();
  record.account = normalized;

  if (!isIndexedDBAvailable()) {
    memoryStore.set(normalized, record);
    return;
  }

  try {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const request = store.put(record);

      request.onsuccess = () => {
        resolve();
      };
      request.onerror = () => {
        reject(request.error);
      };
    });
  } catch {
    memoryStore.set(normalized, record);
  }
};

const idbDelete = async (account: string): Promise<void> => {
  const normalized = account.toLowerCase();
  if (!isIndexedDBAvailable()) {
    memoryStore.delete(normalized);
    return;
  }

  try {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const request = store.delete(normalized);

      request.onsuccess = () => {
        resolve();
      };
      request.onerror = () => {
        reject(request.error);
      };
    });
  } catch {
    memoryStore.delete(normalized);
  }
};

const idbGetAllKeys = async (): Promise<string[]> => {
  if (!isIndexedDBAvailable()) {
    return Array.from(memoryStore.keys());
  }

  try {
    const db = await openDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const request = store.getAllKeys();

      request.onsuccess = () => {
        resolve((request.result as string[]) || []);
      };
      request.onerror = () => {
        reject(request.error);
      };
    });
  } catch {
    return Array.from(memoryStore.keys());
  }
};

const PASSKEY_RP_NAME = "SpooVault";

/**
 * Base64url helpers (kept local so the service has no dependency on the WebAuthn payload format).
 */
const bytesToBase64Url = (bytes: Uint8Array): string => {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const base64UrlToBytes = (value: string): Uint8Array => {
  let b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

interface PasskeyProtection {
  credentialId: string;
  prfSalt: string;
  encryptedPrivateKey: string;
}

/**
 * Register a hardware-backed WebAuthn passkey (TouchID / FaceID / YubiKey) with the PRF
 * extension enabled and encrypt `privateKey` with the derived hardware key.
 *
 * Returns `null` (never throws) when WebAuthn is unavailable, the authenticator does not
 * support PRF, or the user cancels — the caller then falls back to PIN/passphrase protection.
 */
const createPasskeyProtection = async (
  account: string,
  privateKey: string
): Promise<PasskeyProtection | null> => {
  if (!isWebAuthnAvailable()) {
    return null;
  }

  const rpId = getRelyingPartyId();
  const prfSalt = generatePrfSalt();

  try {
    const registration = await registerPasskey({
      rpId,
      rpName: PASSKEY_RP_NAME,
      userName: account,
      userDisplayName: account,
      challenge: generateChallenge(),
      prfSalt,
    });

    if (!registration.prfEnabled) {
      // Authenticator does not support the PRF extension, so no hardware-backed key can
      // be derived. Fall back to PIN/passphrase protection.
      return null;
    }

    // Most authenticators only return the PRF output on *authentication*, so issue a
    // follow-up assertion with the same salt to obtain the derived bytes.
    let prfOutput = registration.prfOutput;
    if (!prfOutput) {
      prfOutput = await authenticatePasskey({
        rpId,
        challenge: generateChallenge(),
        prfSalt,
        credentialId: registration.credentialId,
      });
    }

    // Fold the PRF output into a non-extractable AES-256-GCM key and encrypt the private key.
    const aesKey = await deriveAesKeyFromPrfOutput(prfOutput, prfSalt);
    const encryptedPrivateKey = await encryptWithPrfKey(privateKey, aesKey);

    return {
      credentialId: registration.credentialId,
      prfSalt: bytesToBase64Url(prfSalt),
      encryptedPrivateKey,
    };
  } catch {
    // Registration cancelled, PRF unsupported, or any other failure: fall back to
    // PIN/passphrase protection so the user is never left without a working keyring.
    return null;
  }
};

/**
 * Unlock a passkey-protected record by authenticating with the hardware authenticator
 * and decrypting with the re-derived hardware key.
 */
const decryptRecordWithPasskey = async (record: KeyPairRecord): Promise<string> => {
  const prfSalt = base64UrlToBytes(record.passkeyPrfSalt || "");
  const prfOutput = await authenticatePasskey({
    rpId: getRelyingPartyId(),
    challenge: generateChallenge(),
    prfSalt,
    credentialId: record.passkeyCredentialId || undefined,
  });
  const aesKey = await deriveAesKeyFromPrfOutput(prfOutput, prfSalt);
  return decryptWithPrfKey(record.passkeyEncryptedPrivateKey || "", aesKey);
};

export const clientKeyringService = {
  /**
   * Check if a keypair exists locally in IndexedDB for the given account.
   */
  async hasKeyPair(account: string): Promise<boolean> {
    if (!account) return false;
    const record = await idbGet(account);
    return (
      !!record?.publicKey &&
      (!!record?.encryptedPrivateKey || !!record?.passkeyEncryptedPrivateKey)
    );
  },

  /**
   * Retrieve the stored keypair metadata record for an account.
   */
  async getKeyPairRecord(account: string): Promise<KeyPairRecord | null> {
    if (!account) return null;
    return idbGet(account);
  },

  /**
   * Retrieve the stored public key string (Base64 SPKI) without requiring PIN decryption.
   */
  async getStoredPublicKey(account: string): Promise<string | null> {
    if (!account) return null;
    const record = await idbGet(account);
    return record?.publicKey || null;
  },

  /**
   * Generate a new Web Crypto ECDH P-256 keypair, encrypt the private key with user PIN/passphrase
   * and/or a hardware-backed WebAuthn passkey (TouchID / FaceID / YubiKey), and store in IndexedDB.
   * Caches the unlocked private key in memory for the active session.
   */
  async generateAndSaveKeyPair(
    account: string,
    pinOrPassphrase?: string,
    options: GenerateKeyPairOptions = {}
  ): Promise<{ publicKey: string }> {
    if (!account) {
      throw new Error("Account address is required to generate a keypair");
    }

    const normalized = account.toLowerCase();
    const { publicKey, privateKey } = await generateECIESKeyPairBase64();

    // Attempt to protect the keyring with a hardware-backed WebAuthn passkey (PRF extension).
    const passkey =
      options.enablePasskey !== false
        ? await createPasskeyProtection(normalized, privateKey)
        : null;

    const { passphrase, isCustomPin } = getEffectivePassphrase(normalized, pinOrPassphrase);

    // When a passkey was registered and the user did not set a custom PIN, the deterministic
    // default-derivation blob is intentionally NOT persisted so the private key is only
    // recoverable through the hardware authenticator (no weaker fallback exists).
    const protectWithPasskeyOnly = !!passkey && !isCustomPin;
    const encryptedPrivateKey = protectWithPasskeyOnly
      ? ""
      : await secretsService.encryptWithPassphrase(
          privateKey,
          passphrase,
          PBKDF2_ITERATIONS
        );

    const now = Date.now();
    const record: KeyPairRecord = {
      account: normalized,
      publicKey,
      encryptedPrivateKey,
      createdAt: now,
      updatedAt: now,
      hasPin: isCustomPin,
      hasPasskey: !!passkey,
      passkeyCredentialId: passkey?.credentialId,
      passkeyPrfSalt: passkey?.prfSalt,
      passkeyEncryptedPrivateKey: passkey?.encryptedPrivateKey,
    };

    await idbPut(record);
    sessionKeyCache.set(normalized, privateKey);

    return { publicKey };
  },

  /**
   * Save an existing private and public key pair into the IndexedDB keyring.
   */
  async saveKeyPair(
    account: string,
    publicKey: string,
    privateKey: string,
    pinOrPassphrase?: string
  ): Promise<void> {
    if (!account || !publicKey || !privateKey) {
      throw new Error("Account, publicKey, and privateKey are required");
    }

    // Validate keys by attempting to import them
    await importECIESPublicKey(publicKey);
    await importECIESPrivateKey(privateKey);

    const normalized = account.toLowerCase();
    const { passphrase, isCustomPin } = getEffectivePassphrase(normalized, pinOrPassphrase);

    const encryptedPrivateKey = await secretsService.encryptWithPassphrase(
      privateKey,
      passphrase,
      PBKDF2_ITERATIONS
    );

    const existing = await idbGet(normalized);
    const now = Date.now();
    const record: KeyPairRecord = {
      account: normalized,
      publicKey,
      encryptedPrivateKey,
      createdAt: existing?.createdAt || now,
      updatedAt: now,
      hasPin: isCustomPin,
    };

    await idbPut(record);
    sessionKeyCache.set(normalized, privateKey);
  },

  /**
   * Retrieve and decrypt the client-side private key (Base64 PKCS#8) from IndexedDB.
   * If already unlocked in session cache, returns immediately.
   *
   * For passkey-protected keyrings, unlock happens via the hardware authenticator
   * (TouchID / FaceID / YubiKey) when no PIN is supplied; a supplied PIN/passphrase
   * decrypts the PIN-encrypted fallback blob instead.
   */
  async getDecryptedPrivateKey(
    account: string,
    pinOrPassphrase?: string
  ): Promise<string> {
    if (!account) {
      throw new Error("Account address is required");
    }

    const normalized = account.toLowerCase();
    const cached = sessionKeyCache.get(normalized);
    if (cached) {
      return cached;
    }

    const record = await idbGet(normalized);
    if (!record || (!record.encryptedPrivateKey && !record.passkeyEncryptedPrivateKey)) {
      throw new Error(
        `No local encryption keypair found for wallet ${account}. Please generate one in your Profile page.`
      );
    }

    const trimmedPin = pinOrPassphrase?.trim();

    // Hardware-backed unlock path (TouchID / FaceID / YubiKey) via the WebAuthn PRF extension.
    if (
      !trimmedPin &&
      record.hasPasskey &&
      record.passkeyCredentialId &&
      record.passkeyPrfSalt &&
      record.passkeyEncryptedPrivateKey
    ) {
      try {
        const privateKey = await decryptRecordWithPasskey(record);
        sessionKeyCache.set(normalized, privateKey);
        return privateKey;
      } catch (err) {
        const cancelled = err instanceof WebAuthnError && err.code === "NOT_ALLOWED";
        if (record.hasPin && record.encryptedPrivateKey) {
          // Smooth fallback: the keyring also has a PIN-encrypted copy.
          throw new Error(
            cancelled
              ? "Passkey authentication cancelled. Unlock with your PIN/passphrase instead."
              : "Passkey authentication failed. Unlock with your PIN/passphrase instead."
          );
        }
        throw new Error(
          cancelled
            ? "Passkey authentication cancelled. Please try again when you are ready to unlock."
            : "Passkey authentication failed. Please verify your hardware authenticator."
        );
      }
    }

    // PIN / default passphrase path (also the explicit-PIN fallback for passkey records).
    if (!record.encryptedPrivateKey) {
      throw new Error(
        "This keyring is protected by a hardware passkey. Please unlock with your authenticator (TouchID / FaceID / YubiKey)."
      );
    }

    const { passphrase } = getEffectivePassphrase(normalized, pinOrPassphrase);

    try {
      const privateKey = await secretsService.decryptWithPassphrase(
        record.encryptedPrivateKey,
        passphrase
      );
      sessionKeyCache.set(normalized, privateKey);
      return privateKey;
    } catch {
      throw new Error(
        record.hasPin
          ? "Incorrect PIN or passphrase. Please verify your PIN."
          : "Failed to decrypt client private key from secure storage."
      );
    }
  },

  /**
   * Check if the private key for an account is currently unlocked in the memory session.
   */
  isUnlocked(account: string): boolean {
    if (!account) return false;
    return sessionKeyCache.has(account.toLowerCase());
  },

  /**
   * Lock an account by removing its decrypted private key from the in-memory session cache.
   */
  lockAccount(account: string): void {
    if (account) {
      sessionKeyCache.delete(account.toLowerCase());
    }
  },

  /**
   * Clear all unlocked session keys from memory.
   */
  clearSessionCache(): void {
    sessionKeyCache.clear();
  },

  /**
   * Delete the keypair for an account from IndexedDB and session cache.
   */
  async deleteKeyPair(account: string): Promise<void> {
    if (!account) return;
    const normalized = account.toLowerCase();
    sessionKeyCache.delete(normalized);
    await idbDelete(normalized);
  },

  /**
   * Export a secure, passphrase-encrypted JSON backup of the keypair.
   */
  async exportKeyBackup(
    account: string,
    backupPassphrase: string,
    currentPin?: string
  ): Promise<string> {
    if (!account) throw new Error("Account is required");
    if (!backupPassphrase || !backupPassphrase.trim()) {
      throw new Error("A secure backup passphrase is required");
    }

    const normalized = account.toLowerCase();
    const privateKey = await this.getDecryptedPrivateKey(normalized, currentPin);
    const publicKey = (await this.getStoredPublicKey(normalized)) || "";

    const encryptedForBackup = await secretsService.encryptWithPassphrase(
      privateKey,
      backupPassphrase.trim(),
      PBKDF2_ITERATIONS
    );

    const backupPayload: KeyPairBackupPayload = {
      version: "spoovault-keyring-backup-v1",
      account: normalized,
      publicKey: publicKey || "",
      encryptedPrivateKey: encryptedForBackup,
      exportedAt: new Date().toISOString(),
    };

    return JSON.stringify(backupPayload, null, 2);
  },

  /**
   * Import a keypair from a passphrase-protected backup file.
   */
  async importKeyBackup(
    account: string,
    backupJson: string,
    backupPassphrase: string,
    newPin?: string
  ): Promise<{ publicKey: string }> {
    if (!account) throw new Error("Account is required");
    if (!backupPassphrase) throw new Error("Backup passphrase is required");

    let parsed: KeyPairBackupPayload;
    try {
      parsed = JSON.parse(backupJson);
    } catch {
      throw new Error("Invalid backup file: Malformed JSON");
    }

    if (parsed.version !== "spoovault-keyring-backup-v1") {
      throw new Error(`Unsupported backup format version: ${parsed.version}`);
    }

    const normalized = account.toLowerCase();
    if (parsed.account && parsed.account.toLowerCase() !== normalized) {
      throw new Error(
        `Backup file was created for wallet ${parsed.account}, but active account is ${account}`
      );
    }

    let decryptedPrivateKey: string;
    try {
      decryptedPrivateKey = await secretsService.decryptWithPassphrase(
        parsed.encryptedPrivateKey,
        backupPassphrase
      );
    } catch {
      throw new Error("Failed to decrypt backup: Incorrect backup passphrase");
    }

    await this.saveKeyPair(
      normalized,
      parsed.publicKey,
      decryptedPrivateKey,
      newPin
    );

    return { publicKey: parsed.publicKey };
  },

  /**
   * List all accounts currently stored in the keyring.
   */
  async listAccounts(): Promise<string[]> {
    return idbGetAllKeys();
  },
};
