import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  WebAuthnError,
  authenticatePasskey,
  decryptWithPrfKey,
  deriveAesKeyFromPrfOutput,
  encryptWithPrfKey,
  generateChallenge,
  generatePrfSalt,
  getRelyingPartyId,
  isPlatformAuthenticatorAvailable,
  isWebAuthnAvailable,
  registerPasskey,
} from "../services/webauthn.service";
import { installWebAuthnMock, uninstallWebAuthnMock } from "./helpers/webauthnMock";

const RP_ID = "localhost";
const RP_NAME = "SpooVault";
const USER = "0x71C838936352937A71E976BBE84e941E79409932";

describe("WebAuthnService (Passkeys / PRF extension)", () => {
  beforeEach(() => {
    uninstallWebAuthnMock();
  });

  afterEach(() => {
    uninstallWebAuthnMock();
  });

  describe("Capability detection", () => {
    it("should report WebAuthn as unavailable when the API is not exposed", () => {
      expect(isWebAuthnAvailable()).toBe(false);
      expect(getRelyingPartyId()).toBe("localhost");
    });

    it("should report WebAuthn as available once the API is exposed", () => {
      installWebAuthnMock();
      expect(isWebAuthnAvailable()).toBe(true);
    });

    it("should report the platform authenticator as available", async () => {
      installWebAuthnMock();
      await expect(isPlatformAuthenticatorAvailable()).resolves.toBe(true);
    });
  });

  describe("Passkey registration", () => {
    it("should register a credential with PRF enabled and return a base64url id", async () => {
      const mock = installWebAuthnMock({ returnPrfAtRegistration: true });
      const salt = generatePrfSalt();

      const result = await registerPasskey({
        rpId: RP_ID,
        rpName: RP_NAME,
        userName: USER,
        challenge: generateChallenge(),
        prfSalt: salt,
      });

      expect(result.credentialId).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(result.prfEnabled).toBe(true);
      expect(result.prfOutput).toBeDefined();
      expect(result.prfOutput!.length).toBe(32);
      expect(mock.create).toHaveBeenCalledTimes(1);

      // The PRF eval salt must be forwarded verbatim to the authenticator
      const createArgs = mock.create.mock.calls[0][0] as CredentialCreationOptions;
      const prfEval = (createArgs.publicKey as PublicKeyCredentialCreationOptions)
        .extensions as { prf?: { eval?: { first?: BufferSource } } };
      expect(prfEval.prf!.eval!.first).toEqual(salt);
    });

    it("should report prfEnabled=false when the authenticator does not support PRF", async () => {
      installWebAuthnMock({ prfEnabledAtRegistration: false });
      const result = await registerPasskey({
        rpId: RP_ID,
        rpName: RP_NAME,
        userName: USER,
        challenge: generateChallenge(),
        prfSalt: generatePrfSalt(),
      });
      expect(result.prfEnabled).toBe(false);
      expect(result.prfOutput).toBeUndefined();
    });

    it("should throw WebAuthnError NOT_ALLOWED when the user cancels registration", async () => {
      installWebAuthnMock({ registrationThrows: true, registrationErrorName: "NotAllowedError" });
      await expect(
        registerPasskey({
          rpId: RP_ID,
          rpName: RP_NAME,
          userName: USER,
          challenge: generateChallenge(),
          prfSalt: generatePrfSalt(),
        })
      ).rejects.toMatchObject({ code: "NOT_ALLOWED" });
    });

    it("should throw WebAuthnError NOT_SUPPORTED when WebAuthn is unavailable", async () => {
      await expect(
        registerPasskey({
          rpId: RP_ID,
          rpName: RP_NAME,
          userName: USER,
          challenge: generateChallenge(),
          prfSalt: generatePrfSalt(),
        })
      ).rejects.toMatchObject({ code: "NOT_SUPPORTED" });
    });
  });

  describe("Passkey authentication", () => {
    it("should return a deterministic 32-byte PRF output for the same credential/salt", async () => {
      installWebAuthnMock({ returnPrfAtRegistration: true });
      const salt = generatePrfSalt();
      const registration = await registerPasskey({
        rpId: RP_ID,
        rpName: RP_NAME,
        userName: USER,
        challenge: generateChallenge(),
        prfSalt: salt,
      });

      const first = await authenticatePasskey({
        rpId: RP_ID,
        challenge: generateChallenge(),
        prfSalt: salt,
        credentialId: registration.credentialId,
      });
      const second = await authenticatePasskey({
        rpId: RP_ID,
        challenge: generateChallenge(),
        prfSalt: salt,
        credentialId: registration.credentialId,
      });

      expect(first.length).toBe(32);
      expect(second).toEqual(first);
    });

    it("should throw WebAuthnError PRF_OUTPUT_MISSING when the assertion lacks PRF results", async () => {
      installWebAuthnMock({ returnPrfAtAuthentication: false });
      await expect(
        authenticatePasskey({
          rpId: RP_ID,
          challenge: generateChallenge(),
          prfSalt: generatePrfSalt(),
          credentialId: "abc123",
        })
      ).rejects.toMatchObject({ code: "PRF_OUTPUT_MISSING" });
    });

    it("should throw WebAuthnError NOT_ALLOWED when the user cancels authentication", async () => {
      installWebAuthnMock({ authenticationThrows: true, authenticationErrorName: "NotAllowedError" });
      await expect(
        authenticatePasskey({
          rpId: RP_ID,
          challenge: generateChallenge(),
          prfSalt: generatePrfSalt(),
          credentialId: "abc123",
        })
      ).rejects.toMatchObject({ code: "NOT_ALLOWED" });
    });

    it("should surface a typed WebAuthnError class", async () => {
      installWebAuthnMock({ authenticationThrows: true, authenticationErrorName: "NotAllowedError" });
      try {
        await authenticatePasskey({
          rpId: RP_ID,
          challenge: generateChallenge(),
          prfSalt: generatePrfSalt(),
          credentialId: "abc123",
        });
        expect.unreachable("expected authentication to reject");
      } catch (err) {
        expect(err).toBeInstanceOf(WebAuthnError);
        expect((err as WebAuthnError).code).toBe("NOT_ALLOWED");
      }
    });
  });

  describe("PRF key derivation & encryption", () => {
    it("should derive a non-extractable AES-256-GCM key from the PRF output", async () => {
      const prfOutput = new Uint8Array(32).fill(7);
      const salt = generatePrfSalt();

      const key = await deriveAesKeyFromPrfOutput(prfOutput, salt);

      expect(key.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
      expect(key.extractable).toBe(false);
      expect(key.usages).toEqual(["encrypt", "decrypt"]);
    });

    it("should encrypt and decrypt round-trip with the same derived key", async () => {
      const prfOutput = new Uint8Array(32).fill(42);
      const salt = generatePrfSalt();
      const key = await deriveAesKeyFromPrfOutput(prfOutput, salt);

      const plaintext = "private-key-pkcs8-base64-material";
      const payload = await encryptWithPrfKey(plaintext, key);
      expect(payload).not.toContain(plaintext);

      const decrypted = await decryptWithPrfKey(payload, key);
      expect(decrypted).toBe(plaintext);
    });

    it("should fail to decrypt when the derived key differs (wrong PRF output)", async () => {
      const salt = generatePrfSalt();
      const key = await deriveAesKeyFromPrfOutput(new Uint8Array(32).fill(1), salt);
      const payload = await encryptWithPrfKey("secret", key);

      const wrongKey = await deriveAesKeyFromPrfOutput(new Uint8Array(32).fill(2), salt);
      await expect(decryptWithPrfKey(payload, wrongKey)).rejects.toThrow(
        "Failed to decrypt passkey-encrypted payload"
      );
    });

    it("should reject malformed or unsupported payloads", async () => {
      const key = await deriveAesKeyFromPrfOutput(new Uint8Array(32).fill(3), generatePrfSalt());
      await expect(decryptWithPrfKey("not-json", key)).rejects.toThrow(
        "Invalid passkey-encrypted payload"
      );
      await expect(
        decryptWithPrfKey(JSON.stringify({ version: "v0", iv: "", ciphertext: "" }), key)
      ).rejects.toThrow("Unsupported passkey payload version");
    });
  });
});
