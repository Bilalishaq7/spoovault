/**
 * WebAuthn (Passkeys / TouchID / FaceID / YubiKey) PRF-extension helpers.
 *
 * The WebAuthn Level 3 **PRF** (pseudo-random function) extension lets a site ask a
 * hardware authenticator to derive a deterministic pseudo-random value from a
 * per-site salt. The HMAC-SHA-256 master secret lives *inside* the secure enclave /
 * authenticator and never leaves it; the site only receives the derived output for
 * the exact salt it supplies. By feeding the same salt at registration and at every
 * subsequent authentication, the same derived bytes are reproducibly obtained — which
 * makes them usable as the root material for a hardware-backed keyring encryption key.
 *
 * The derived output is immediately folded into a **non-extractable** AES-256-GCM
 * CryptoKey via HKDF-SHA-256, so the raw key bytes are never held in JavaScript after
 * import and cannot be exported from Web Crypto.
 */

export type WebAuthnErrorCode =
  | "NOT_SUPPORTED"
  | "NOT_ALLOWED"
  | "PRF_NOT_ENABLED"
  | "PRF_OUTPUT_MISSING"
  | "UNKNOWN";

/** Typed error carrying a machine-readable code so callers can react to cancellations vs. failures. */
export class WebAuthnError extends Error {
  readonly code: WebAuthnErrorCode;

  constructor(message: string, code: WebAuthnErrorCode) {
    super(message);
    this.name = "WebAuthnError";
    this.code = code;
  }
}

export const PRF_SALT_LENGTH = 32;
export const PRF_OUTPUT_LENGTH = 32;

const PRF_HKDF_INFO = new TextEncoder().encode("spoovault-keyring-passkey-v1");
const PRF_PAYLOAD_VERSION = "prf-aes256gcm-v1";

/** @internal */
type WebAuthnScope = {
  PublicKeyCredential?: typeof PublicKeyCredential;
  navigator?: { credentials?: CredentialsContainer };
  location?: { hostname?: string };
  crypto?: Crypto;
};

const getGlobalScope = (): WebAuthnScope => {
  const scope: unknown =
    (typeof window !== "undefined" ? window : undefined) ??
    (typeof globalThis !== "undefined" ? globalThis : undefined);
  return (scope ?? {}) as WebAuthnScope;
};

const getWebCrypto = (): Crypto => {
  const cryptoObj = getGlobalScope().crypto;
  if (!cryptoObj?.subtle) {
    throw new WebAuthnError(
      "Web Crypto API (crypto.subtle) is not available in this environment",
      "NOT_SUPPORTED"
    );
  }
  return cryptoObj;
};

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

const getPrfExtensionResults = (
  credential: PublicKeyCredential
): AuthenticationExtensionsPRFOutputs => {
  const results = credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
    prf?: AuthenticationExtensionsPRFOutputs;
  };
  return results.prf ?? {};
};

/** Normalize a `BufferSource` (ArrayBuffer or typed array view) into a `Uint8Array`. */
const bufferSourceToBytes = (source: BufferSource): Uint8Array => {
  if (source instanceof ArrayBuffer) {
    return new Uint8Array(source);
  }
  return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
};

const normalizeCredentialError = (err: unknown, prefix: string): WebAuthnError => {
  const raw = (err as { name?: string } | undefined)?.name || (err as Error | undefined)?.message || "";
  if (/NotAllowedError|not allowed|cancel(led|l)?ed|dismissed|user gesture/i.test(raw)) {
    return new WebAuthnError(`${prefix}: the request was cancelled or declined by the user.`, "NOT_ALLOWED");
  }
  if (/NotSupportedError|not supported|unsupported/i.test(raw)) {
    return new WebAuthnError(`${prefix}: WebAuthn / PRF is not supported by this device or authenticator.`, "NOT_SUPPORTED");
  }
  return new WebAuthnError(`${prefix}: ${raw || "unknown error"}`, "UNKNOWN");
};

/** Check whether the current environment exposes the WebAuthn API at all. */
export const isWebAuthnAvailable = (): boolean => {
  const scope = getGlobalScope();
  return !!scope.PublicKeyCredential && !!scope.navigator?.credentials;
};

/** Best-effort check for a platform authenticator (TouchID / FaceID / Windows Hello). */
export const isPlatformAuthenticatorAvailable = async (): Promise<boolean> => {
  const scope = getGlobalScope();
  if (typeof scope.PublicKeyCredential?.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
    return false;
  }
  try {
    return await scope.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
};

/** Generate a fresh random PRF salt (the per-site eval input shared with the authenticator). */
export const generatePrfSalt = (length: number = PRF_SALT_LENGTH): Uint8Array => {
  const salt = new Uint8Array(length);
  getWebCrypto().getRandomValues(salt);
  return salt;
};

/** Generate a fresh random challenge for a WebAuthn ceremony. */
export const generateChallenge = (length: number = 32): Uint8Array => {
  const challenge = new Uint8Array(length);
  getWebCrypto().getRandomValues(challenge);
  return challenge;
};

/** Resolve the WebAuthn relying-party id from the current origin (falls back to localhost). */
export const getRelyingPartyId = (): string => {
  const hostname = getGlobalScope().location?.hostname;
  return hostname && hostname.length > 0 ? hostname : "localhost";
};

export interface RegisterPasskeyOptions {
  rpId: string;
  rpName: string;
  /** Stable user handle / name — typically the wallet account address. */
  userName: string;
  userDisplayName?: string;
  challenge: Uint8Array;
  /** PRF eval input. MUST be persisted and reused verbatim at every authentication. */
  prfSalt: Uint8Array;
  /** Base64url credential ids to exclude (already-registered passkeys for this account). */
  excludeCredentialIds?: string[];
  timeoutMs?: number;
}

export interface RegisterPasskeyResult {
  /** Base64url credential id to persist for later authentication. */
  credentialId: string;
  /** Whether the authenticator enabled the PRF extension for this credential. */
  prfEnabled: boolean;
  /**
   * PRF-derived output, when the authenticator returns it directly on the registration
   * response. Most authenticators only return it on authentication, in which case the
   * caller must issue a follow-up assertion via {@link authenticatePasskey}.
   */
  prfOutput?: Uint8Array;
}

/**
 * Register a hardware-backed passkey credential with the PRF extension enabled.
 * The authenticator derives a secret bound to the supplied `prfSalt`; the same salt
 * at authentication reproduces the same derived output.
 */
export const registerPasskey = async (
  options: RegisterPasskeyOptions
): Promise<RegisterPasskeyResult> => {
  const scope = getGlobalScope();
  if (!scope.PublicKeyCredential || !scope.navigator?.credentials) {
    throw new WebAuthnError("WebAuthn is not available in this browser or device.", "NOT_SUPPORTED");
  }

  const publicKey: PublicKeyCredentialCreationOptions = {
    challenge: options.challenge as BufferSource,
    rp: { id: options.rpId, name: options.rpName },
    user: {
      id: new TextEncoder().encode(options.userName),
      name: options.userName,
      displayName: options.userDisplayName || options.userName,
    },
    pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
    timeout: options.timeoutMs ?? 60_000,
    attestation: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
    extensions: {
      prf: { eval: { first: options.prfSalt as BufferSource } },
    },
  };

  if (options.excludeCredentialIds?.length) {
    publicKey.excludeCredentials = options.excludeCredentialIds.map((id) => ({
      type: "public-key",
      id: base64UrlToBytes(id) as BufferSource,
    }));
  }

  let credential: PublicKeyCredential | null;
  try {
    credential = (await scope.navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  } catch (err) {
    throw normalizeCredentialError(err, "Passkey registration failed");
  }
  if (!credential) {
    throw new WebAuthnError("Passkey registration returned no credential.", "UNKNOWN");
  }

  const prf = getPrfExtensionResults(credential);
  return {
    credentialId: bytesToBase64Url(bufferSourceToBytes(credential.rawId)),
    prfEnabled: !!prf.enabled,
    prfOutput: prf.results?.first ? bufferSourceToBytes(prf.results.first) : undefined,
  };
};

export interface AuthenticatePasskeyOptions {
  rpId: string;
  challenge: Uint8Array;
  /** Same PRF eval input used at registration — reproduces the same derived output. */
  prfSalt: Uint8Array;
  /** Base64url credential id. Omit to let the platform offer discoverable credentials. */
  credentialId?: string;
  timeoutMs?: number;
}

/**
 * Authenticate with the registered passkey and return the PRF-derived output bytes
 * (32 bytes, HMAC-SHA-256 based). The same `prfSalt` as registration yields the same
 * output, which is what makes the bytes usable as a hardware-backed decryption key.
 */
export const authenticatePasskey = async (
  options: AuthenticatePasskeyOptions
): Promise<Uint8Array> => {
  const scope = getGlobalScope();
  if (!scope.PublicKeyCredential || !scope.navigator?.credentials) {
    throw new WebAuthnError("WebAuthn is not available in this browser or device.", "NOT_SUPPORTED");
  }

  const publicKey: PublicKeyCredentialRequestOptions = {
    challenge: options.challenge as BufferSource,
    rpId: options.rpId,
    timeout: options.timeoutMs ?? 60_000,
    userVerification: "required",
    extensions: {
      prf: { eval: { first: options.prfSalt as BufferSource } },
    },
  };

  if (options.credentialId) {
    publicKey.allowCredentials = [
      { type: "public-key", id: base64UrlToBytes(options.credentialId) as BufferSource },
    ];
  }

  let assertion: PublicKeyCredential | null;
  try {
    assertion = (await scope.navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  } catch (err) {
    throw normalizeCredentialError(err, "Passkey authentication failed");
  }
  if (!assertion) {
    throw new WebAuthnError("Passkey authentication returned no assertion.", "UNKNOWN");
  }

  const prf = getPrfExtensionResults(assertion);
  const first = prf.results?.first;
  if (!first) {
    throw new WebAuthnError(
      "The authenticator did not return a PRF-derived output.",
      "PRF_OUTPUT_MISSING"
    );
  }
  return bufferSourceToBytes(first);
};

/**
 * Fold PRF-derived output bytes into a non-extractable AES-256-GCM CryptoKey via
 * HKDF-SHA-256. The key is created with `extractable: false`, so the raw key bytes
 * never leave the Web Crypto API after this point.
 */
export const deriveAesKeyFromPrfOutput = async (
  prfOutput: Uint8Array,
  salt: Uint8Array
): Promise<CryptoKey> => {
  const subtle = getWebCrypto().subtle;
  const keyMaterial = await subtle.importKey("raw", prfOutput as BufferSource, "HKDF", false, [
    "deriveKey",
  ]);
  return subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt as BufferSource,
      info: PRF_HKDF_INFO,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false, // non-extractable
    ["encrypt", "decrypt"]
  );
};

export interface PrfEncryptedPayload {
  version: string;
  iv: string; // base64url
  ciphertext: string; // base64url
}

/** Encrypt a plaintext string (e.g. the keyring private key) with the PRF-derived AES key. */
export const encryptWithPrfKey = async (
  plaintext: string,
  aesKey: CryptoKey
): Promise<string> => {
  const iv = new Uint8Array(12);
  getWebCrypto().getRandomValues(iv);

  const ciphertext = await getWebCrypto().subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    aesKey,
    new TextEncoder().encode(plaintext) as BufferSource
  );

  const payload: PrfEncryptedPayload = {
    version: PRF_PAYLOAD_VERSION,
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(new Uint8Array(ciphertext)),
  };
  return JSON.stringify(payload);
};

/** Decrypt a payload produced by {@link encryptWithPrfKey}. Wrong key ⇒ AES-GCM tag failure (throws). */
export const decryptWithPrfKey = async (
  payloadJson: string,
  aesKey: CryptoKey
): Promise<string> => {
  let payload: PrfEncryptedPayload;
  try {
    payload = JSON.parse(payloadJson) as PrfEncryptedPayload;
  } catch {
    throw new Error("Invalid passkey-encrypted payload");
  }
  if (payload.version !== PRF_PAYLOAD_VERSION) {
    throw new Error(`Unsupported passkey payload version: ${payload.version}`);
  }

  const iv = base64UrlToBytes(payload.iv);
  const ciphertext = base64UrlToBytes(payload.ciphertext);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await getWebCrypto().subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource },
      aesKey,
      ciphertext as BufferSource
    );
  } catch {
    throw new Error("Failed to decrypt passkey-encrypted payload");
  }
  return new TextDecoder().decode(plaintext);
};
