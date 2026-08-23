import { expect } from "chai";
import hre from "hardhat";

const { ethers } = hre;

describe("SpooVault EVM Contract Unit Tests & ERC-165 Interoperability (Issue #110)", function () {
  let spooVault;
  let consumer;
  let owner;
  let guardian1;
  let guardian2;
  let beneficiary;

  beforeEach(async function () {
    [owner, guardian1, guardian2, beneficiary] = await ethers.getSigners();

    const SpooVault = await ethers.getContractFactory("SpooVault");
    spooVault = await SpooVault.deploy();
    await spooVault.waitForDeployment();

    const ThirdPartyConsumer = await ethers.getContractFactory("ThirdPartyConsumer");
    consumer = await ThirdPartyConsumer.deploy(await spooVault.getAddress());
    await consumer.waitForDeployment();
  });

  describe("ERC-165 Interface Detection", function () {
    it("should report true for ISpooVault and ERC-721 interfaces", async function () {
      // Calculate ISpooVault interfaceId
      const ISpooVaultInterface = new ethers.Interface([
        "function registerPublicKey(string) external",
        "function checkAccess(uint256,address) external view returns (uint8)",
        "function hasActiveAccess(uint256,address) external view returns (bool)",
        "function hasVaultToken(address,uint256) external view returns (bool)",
        "function getTokenVault(uint256) external view returns (uint256)",
        "function getVault(uint256) external view returns (uint256,address,string,string,address[],uint256,bool,uint256)",
        "function getVaultReleaseState(uint256) external view returns (bool,uint256,uint256,bool)",
        "function requestAccess(uint256) external returns (uint256)",
        "function approveAccess(uint256) external",
        "function approveAccess(uint256,string) external",
        "function revokeAccess(uint256,address) external",
        "function mintAccessToken(uint256,address,string) external returns (uint256)",
        "function burnAccessToken(uint256) external"
      ]);

      let ispooVaultInterfaceId = 0n;
      ISpooVaultInterface.forEachFunction((fn) => {
        const selector = BigInt(fn.selector);
        ispooVaultInterfaceId ^= selector;
      });
      const interfaceIdHex = "0x" + ispooVaultInterfaceId.toString(16).padStart(8, "0");

      expect(await spooVault.supportsInterface(interfaceIdHex)).to.equal(true);
      expect(await consumer.isSpooVaultSupported()).to.equal(true);

      // ERC721 interfaceId = 0x80ac58cd
      expect(await spooVault.supportsInterface("0x80ac58cd")).to.equal(true);

      // Invalid interfaceId = 0xffffffff
      expect(await spooVault.supportsInterface("0xffffffff")).to.equal(false);
    });
  });

  describe("Public Key Registry", function () {
    it("should allow a user to register an X25519 public key", async function () {
      const pubKey = "B64_PUBLIC_KEY_TEST_STRING_12345";
      await expect(spooVault.connect(beneficiary).registerPublicKey(pubKey))
        .to.emit(spooVault, "PublicKeyRegistered")
        .withArgs(beneficiary.address, pubKey);

      const registeredKey = await spooVault.userPublicKeys(beneficiary.address);
      expect(registeredKey).to.equal(pubKey);
    });
  });

  describe("Vault Creation & Guardian Thresholds", function () {
    it("should create a vault with valid threshold and guardian invite list", async function () {
      const guardians = [guardian1.address, guardian2.address];
      const threshold = 2; // threshold out of owner + 2 guardians = 3 total

      const tx = await spooVault.connect(owner).createVault(
        "Executive Vault",
        "Confidential legal documents",
        guardians,
        threshold
      );

      await expect(tx).to.emit(spooVault, "VaultCreated");

      const vault = await spooVault.vaults(1);
      expect(vault.name).to.equal("Executive Vault");
      expect(vault.creator).to.equal(owner.address);
      expect(vault.approvalThreshold).to.equal(threshold);
      expect(vault.isActive).to.equal(true);
    });

    it("should revert vault creation if no external guardians are provided", async function () {
      await expect(
        spooVault.connect(owner).createVault("Single Vault", "Desc", [], 1)
      ).to.be.revertedWithCustomError(spooVault, "AtLeastOneGuardian");
    });

    it("should revert if approval threshold is zero or exceeds total guardian count", async function () {
      const guardians = [guardian1.address];
      await expect(
        spooVault.connect(owner).createVault("Invalid Threshold Vault", "Desc", guardians, 0)
      ).to.be.revertedWithCustomError(spooVault, "InvalidApprovalThreshold");

      await expect(
        spooVault.connect(owner).createVault("Over Threshold Vault", "Desc", guardians, 5)
      ).to.be.revertedWithCustomError(spooVault, "InvalidApprovalThreshold");
    });
  });

  describe("Standardized checkAccess Hook & Consumer Interoperability", function () {
    beforeEach(async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Test Vault", "Desc", guardians, 1);
    });

    it("should return 1 (DOCUMENT_NOT_EXIST) for non-existent document ID", async function () {
      expect(await spooVault.checkAccess(999, beneficiary.address)).to.equal(1);
      expect(await consumer.queryAccessStatus(999, beneficiary.address)).to.equal(1);
    });

    it("should return 0 (GRANTED) for document creator guardian", async function () {
      await spooVault.connect(owner)["addDocument(uint256,string,string,uint8)"](1, "enc-meta", "QmIPFS123", 0);

      expect(await spooVault.checkAccess(1, owner.address)).to.equal(0);
      expect(await consumer.queryAccessStatus(1, owner.address)).to.equal(0);
      expect(await consumer.performAuthorizedAction(1, owner.address)).to.equal(true);
    });

    it("should return 2 (NO_ACCESS) for beneficiary without granted access or NFT", async function () {
      await spooVault.connect(owner)["addDocument(uint256,string,string,uint8)"](1, "enc-meta", "QmIPFS123", 0);

      expect(await spooVault.checkAccess(1, beneficiary.address)).to.equal(2);
      expect(await consumer.queryAccessStatus(1, beneficiary.address)).to.equal(2);

      await expect(
        consumer.performAuthorizedAction(1, beneficiary.address)
      ).to.be.revertedWithCustomError(consumer, "DocumentAccessDenied").withArgs(2);
    });

    it("should return 3 (RELEASE_CONDITION_LOCKED) when post-death condition is not satisfied", async function () {
      // Add document with POST_DEATH_ONLY condition (3)
      await spooVault.connect(owner)["addDocumentWithReleaseCondition(uint256,string,string,uint8,uint8)"](1, "enc-meta", "QmIPFS123", 0, 3);

      expect(await spooVault.checkAccess(1, beneficiary.address)).to.equal(3);
      expect(await consumer.queryAccessStatus(1, beneficiary.address)).to.equal(3);

      await expect(
        consumer.performAuthorizedAction(1, beneficiary.address)
      ).to.be.revertedWithCustomError(consumer, "DocumentAccessDenied").withArgs(3);
    });
  });

  describe("Vault Release State & Proof of Life", function () {
    it("should allow vault creator to record proof of life", async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Inheritance Vault", "Desc", guardians, 1);

      await expect(spooVault.connect(owner).proveLife(1))
        .to.emit(spooVault, "ProofOfLifeRecorded");
    });

    it("should allow vault creator to toggle emergency mode", async function () {
      const guardians = [guardian1.address];
      await spooVault.connect(owner).createVault("Emergency Vault", "Desc", guardians, 1);

      await expect(spooVault.connect(owner).setEmergencyMode(1, true))
        .to.emit(spooVault, "EmergencyModeUpdated")
        .withArgs(1, true);
    });
  });
});
