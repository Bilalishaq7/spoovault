import { vi } from "vitest";

/**
 * Minimal WebAuthn mock that simulates a hardware authenticator with the PRF extension.
 *
 * The mock derives a deterministic 32-byte PRF output per credential id (stored in
 * `prfOutputs`), mirroring how a real authenticator returns the same derived bytes for
 * the same salt/credential on every authentication.
 */

export interface InstallWebAuthnMockOptions {
  available?: boolean;
  /** Whether registration responses report `prf.enabled: true`. */
  prfEnabledAtRegistration?: boolean;
  /** Whether registration responses also carry `prf.results.first` (some authenticators do). */
  returnPrfAtRegistration?: boolean;
  /** Whether authentication responses carry `prf.results.first` (defaults to true). */
  returnPrfAtAuthentication?: boolean;
  /** Throw during registration (e.g. NotAllowedError when the user cancels). */
  registrationThrows?: boolean;
  registrationErrorName?: string;
  /** Throw during authentication (e.g. NotAllowedError when the user cancels). */
  authenticationThrows?: boolean;
  authenticationErrorName?: string;
}

export interface InstalledWebAuthnMock {
  create: ReturnType<typeof vi.fn>;
  get: ReturnType<typeof vi.fn>;
  /** Deterministic PRF output per credential id. */
  prfOutputs: Map<string, Uint8Array>;
  isUserVerifyingPlatformAuthenticatorAvailable: ReturnType<typeof vi.fn>;
}

const randomBytes = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
};

const bytesToBase64Url = (bytes: Uint8Array): string => {
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const makeDomException = (name: string): Error => {
  try {
    return new DOMException(name, name);
  } catch {
    const err = new Error(name);
    err.name = name;
    return err;
  }
};

const makeCredential = (rawId: Uint8Array, prf: unknown) => ({
  id: bytesToBase64Url(rawId),
  rawId,
  type: "public-key",
  getClientExtensionResults: () => ({ prf }),
});

/** Derive a stable credential id from the PRF salt so re-registration is reproducible. */
const credentialIdFromSalt = (salt: Uint8Array): Uint8Array => {
  const idBytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    idBytes[i] = salt[i % salt.length] ^ (i * 7 + 3);
  }
  return idBytes;
};

const readPrfEvalSalt = (publicKey: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions): Uint8Array => {
  const prf = (publicKey.extensions as { prf?: { eval?: { first?: BufferSource } } } | undefined)?.prf;
  const first = prf?.eval?.first;
  return first ? new Uint8Array(first as ArrayBuffer) : new Uint8Array(0);
};

export const installWebAuthnMock = (
  options: InstallWebAuthnMockOptions = {}
): InstalledWebAuthnMock => {
  const {
    available = true,
    prfEnabledAtRegistration = true,
    returnPrfAtRegistration = false,
    returnPrfAtAuthentication = true,
    registrationThrows = false,
    registrationErrorName = "NotAllowedError",
    authenticationThrows = false,
    authenticationErrorName = "NotAllowedError",
  } = options;

  const prfOutputs = new Map<string, Uint8Array>();
  const defaultOutput = randomBytes(32);

  const getOrCreateOutput = (credentialId: string): Uint8Array => {
    let output = prfOutputs.get(credentialId);
    if (!output) {
      output = new Uint8Array(defaultOutput);
      prfOutputs.set(credentialId, output);
    }
    return output;
  };

  const create = vi.fn(async (optionsArg: CredentialCreationOptions) => {
    if (registrationThrows) throw makeDomException(registrationErrorName);
    if (!available) throw new Error("WebAuthn is not available");

    const publicKey = optionsArg.publicKey as PublicKeyCredentialCreationOptions;
    const salt = readPrfEvalSalt(publicKey);
    const rawId = credentialIdFromSalt(salt);
    const credentialId = bytesToBase64Url(rawId);
    const output = getOrCreateOutput(credentialId);

    const prf: Record<string, unknown> = { enabled: prfEnabledAtRegistration };
    if (returnPrfAtRegistration) {
      prf.results = { first: output };
    }
    return makeCredential(rawId, prf);
  });

  const get = vi.fn(async (optionsArg: CredentialRequestOptions) => {
    if (authenticationThrows) throw makeDomException(authenticationErrorName);
    if (!available) throw new Error("WebAuthn is not available");

    const publicKey = optionsArg.publicKey as PublicKeyCredentialRequestOptions;
    const allowed = publicKey.allowCredentials?.[0];
    const rawId = allowed ? new Uint8Array(allowed.id as ArrayBuffer) : randomBytes(16);
    const credentialId = bytesToBase64Url(rawId);
    const output = getOrCreateOutput(credentialId);

    const prf: Record<string, unknown> = {};
    if (returnPrfAtAuthentication) {
      prf.results = { first: output };
    }
    return makeCredential(rawId, prf);
  });

  const mock: InstalledWebAuthnMock = {
    create,
    get,
    prfOutputs,
    isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => true),
  };

  (globalThis as Record<string, unknown>).navigator = { credentials: { create, get } };
  (globalThis as Record<string, unknown>).PublicKeyCredential = {
    isUserVerifyingPlatformAuthenticatorAvailable:
      mock.isUserVerifyingPlatformAuthenticatorAvailable,
  };

  return mock;
};

export const uninstallWebAuthnMock = (): void => {
  delete (globalThis as Record<string, unknown>).PublicKeyCredential;
  delete (globalThis as Record<string, unknown>).navigator;
};
