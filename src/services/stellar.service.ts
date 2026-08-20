// Stellar SDK packages are optional runtime dependencies for Soroban support.
// They are loaded lazily through an eval-style import so that TypeScript's
// static module resolution never fails at build time.
// Contributors who want full Soroban support should run:
//   npm install @stellar/freighter-api @stellar/stellar-sdk
//
// import { isConnected, getAddress } from "@stellar/freighter-api";
// import { rpc } from "@stellar/stellar-sdk";

// ---------------------------------------------------------------------------
// Lightweight freighter shim – replaced by real API when package is present
// ---------------------------------------------------------------------------
type FreighterShim = { isConnected: () => Promise<boolean>; getAddress: () => Promise<string> };
let _freighter: FreighterShim | null = null;

const loadFreighter = async (): Promise<FreighterShim> => {
  if (_freighter) return _freighter;
  try {
    // Use new Function to bypass TypeScript's static import analysis
    const dynamicImport = new Function("specifier", "return import(specifier)");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const mod = await dynamicImport("@stellar/freighter-api") as any;
    _freighter = { isConnected: mod.isConnected, getAddress: mod.getAddress };
  } catch {
    // Package not installed – graceful fallback stubs
    _freighter = {
      isConnected: async () => false,
      getAddress: async () => "",
    };
  }
  return _freighter;
};

export interface StellarVaultData {
  id: number;
  creator: string;
  name: string;
  description: string;
  guardians: string[];
  approvalThreshold: number;
  isActive: boolean;
  createdAt: number;
  network?: "avalanche" | "stellar";
}

export interface StellarTokenData {
  tokenId: number;
  owner: string;
  vaultId: number | null;
  tokenURI: string;
  mintedAt: number | null;
}

export interface StellarDocumentData {
  id: number;
  vaultId: number;
  encryptedMetadata: string;
  ipfsHash: string;
  uploadedBy: string;
  uploadedAt: number;
  requiredAccess: number;
}

export interface StellarPendingApprovalData {
  requestId: number;
  documentId: number;
  vaultId: number;
  vaultName: string;
  requester: string;
  createdAt: number;
  expiresAt: number;
}

let activeAccount: string | null = null;
const sorobanRpcUrl = "https://soroban-testnet.stellar.org";
let contractId = "";

const getContractId = (): string => {
  const cid = import.meta.env.VITE_STELLAR_CONTRACT_ADDRESS as string | undefined;
  return cid || contractId || "";
};

const isConfigured = (): boolean => {
  return !!getContractId();
};

const initialize = async (customContractId?: string): Promise<string | null> => {
  if (customContractId) {
    contractId = customContractId;
  } else {
    contractId = (import.meta.env.VITE_STELLAR_CONTRACT_ADDRESS as string | undefined) || "";
  }

  try {
    const freighter = await loadFreighter();
    const connected = await freighter.isConnected();
    if (connected) {
      const address = await freighter.getAddress();
      activeAccount = address || null;
      return activeAccount;
    }
  } catch (error) {
    console.error("Freighter initialization failed:", error);
  }
  return null;
};

const clear = () => {
  activeAccount = null;
};

const getAccount = (): string | null => activeAccount;

const connectWallet = async (): Promise<string> => {
  const freighter = await loadFreighter();
  const connected = await freighter.isConnected();
  if (!connected) {
    throw new Error("Freighter wallet extension is not installed or enabled");
  }

  const address = await freighter.getAddress();
  if (!address) {
    throw new Error("Failed to get address from Freighter wallet");
  }

  activeAccount = address;
  return address;
};

// Fallback Mock Storage for local development when Freighter/Soroban is not deployed
const getMockStorage = <T,>(key: string, defaults: T): T => {
  try {
    const raw = localStorage.getItem(`spoovault-stellar-mock-${key}`);
    return raw ? (JSON.parse(raw) as T) : defaults;
  } catch {
    return defaults;
  }
};

const saveMockStorage = <T,>(key: string, data: T) => {
  try {
    localStorage.setItem(`spoovault-stellar-mock-${key}`, JSON.stringify(data));
  } catch {
    // ignore storage issues
  }
};

// Mock structures matching Soroban states
interface MockVault {
  id: number;
  creator: string;
  name: string;
  description: string;
  guardians: string[];
  approvalThreshold: number;
  isActive: boolean;
  createdAt: number;
}

interface MockDocument {
  id: number;
  vaultId: number;
  encryptedMetadata: string;
  ipfsHash: string;
  uploadedBy: string;
  uploadedAt: number;
  requiredAccess: number;
  releaseCondition: number;
  shares: Record<string, string>;
}

interface MockRequest {
  requestId: number;
  documentId: number;
  requester: string;
  approvedBy: string[];
  status: number;
  expiresAt: number;
  createdAt: number;
  beneficiaryShares: Record<string, string>;
}

interface MockInvite {
  guardian: string;
  vaultId: number;
  accepted: boolean;
  expiresAt: number;
}

const createVault = async (
  name: string,
  description: string,
  guardians: string[],
  approvalThreshold: number
): Promise<number> => {
  if (!activeAccount) throw new Error("Wallet not connected");

  // If contract is set up, perform genuine Soroban call
  if (isConfigured()) {
    // TODO (Contributor): Build and submit a Soroban transaction here.
    // Use sorobanRpcUrl + contractId with @stellar/stellar-sdk and Freighter.
    // See CONTRIBUTING.md for setup instructions.
    void sorobanRpcUrl; // referenced to avoid unused-variable lint
    console.log("Soroban create_vault: contract skeleton ready at", sorobanRpcUrl);
  }

  // Fallback to Mock Database for instantaneous UI execution and debugging
  const vaults = getMockStorage<MockVault[]>("vaults", []);
  const nextId = vaults.length + 1;
  const newVault: MockVault = {
    id: nextId,
    creator: activeAccount,
    name,
    description,
    guardians: [activeAccount],
    approvalThreshold,
    isActive: true,
    createdAt: Math.floor(Date.now() / 1000),
  };

  vaults.push(newVault);
  saveMockStorage("vaults", vaults);

  // Add invites
  const invites = getMockStorage<MockInvite[]>("invites", []);
  for (const guardian of guardians) {
    if (guardian.toLowerCase() === activeAccount.toLowerCase()) continue;
    invites.push({
      guardian: guardian.trim(),
      vaultId: nextId,
      accepted: false,
      expiresAt: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60,
    });
  }
  saveMockStorage("invites", invites);

  return nextId;
};

const getVault = async (vaultId: number): Promise<StellarVaultData | null> => {
  const vaults = getMockStorage<MockVault[]>("vaults", []);
  const vault = vaults.find((v) => v.id === vaultId);
  return vault || null;
};

const fetchVaultsForAccount = async (account: string): Promise<StellarVaultData[]> => {
  const vaults = getMockStorage<MockVault[]>("vaults", []);
  const target = account.toLowerCase();
  
  // Return vaults where user is a creator or active guardian
  return vaults
    .filter(
      (v) =>
        v.creator.toLowerCase() === target ||
        v.guardians.some((g) => g.toLowerCase() === target)
    )
    .map((v) => ({ ...v, network: "stellar" as const }));
};

const addDocument = async (
  vaultId: number,
  encryptedMetadata: string,
  ipfsHash: string,
  requiredAccess: number,
  releaseCondition = 0,
  guardiansList: string[] = [],
  shares: string[] = []
): Promise<number> => {
  if (!activeAccount) throw new Error("Wallet not connected");

  const docs = getMockStorage<MockDocument[]>("documents", []);
  const nextId = docs.length + 1;

  const sharesMap: Record<string, string> = {};
  guardiansList.forEach((guardian, idx) => {
    sharesMap[guardian] = shares[idx];
  });

  const newDoc: MockDocument = {
    id: nextId,
    vaultId,
    encryptedMetadata,
    ipfsHash,
    uploadedBy: activeAccount,
    uploadedAt: Math.floor(Date.now() / 1000),
    requiredAccess,
    releaseCondition,
    shares: sharesMap,
  };

  docs.push(newDoc);
  saveMockStorage("documents", docs);
  return nextId;
};

const fetchDocumentsForVaults = async (vaultIds: number[]): Promise<StellarDocumentData[]> => {
  const docs = getMockStorage<MockDocument[]>("documents", []);
  const set = new Set(vaultIds);
  return docs.filter((d) => set.has(d.vaultId));
};

const requestAccess = async (documentId: number): Promise<number> => {
  if (!activeAccount) throw new Error("Wallet not connected");

  const requests = getMockStorage<MockRequest[]>("requests", []);
  const nextId = requests.length + 1;

  const newReq: MockRequest = {
    requestId: nextId,
    documentId,
    requester: activeAccount,
    approvedBy: [],
    status: 0, // Pending
    expiresAt: Math.floor(Date.now() / 1000) + 3 * 24 * 60 * 60,
    createdAt: Math.floor(Date.now() / 1000),
    beneficiaryShares: {},
  };

  requests.push(newReq);
  saveMockStorage("requests", requests);
  return nextId;
};

const approveAccess = async (requestId: number, encryptedShareForBeneficiary?: string): Promise<void> => {
  if (!activeAccount) throw new Error("Wallet not connected");

  const requests = getMockStorage<MockRequest[]>("requests", []);
  const reqIdx = requests.findIndex((r) => r.requestId === requestId);
  if (reqIdx === -1) throw new Error("Request not found");

  const req = requests[reqIdx];
  if (req.approvedBy.includes(activeAccount)) {
    throw new Error("Already approved");
  }

  req.approvedBy.push(activeAccount);
  if (encryptedShareForBeneficiary) {
    req.beneficiaryShares[activeAccount] = encryptedShareForBeneficiary;
  }

  // Fetch vault approval threshold
  const docs = getMockStorage<MockDocument[]>("documents", []);
  const doc = docs.find((d) => d.id === req.documentId);
  if (doc) {
    const vaults = getMockStorage<MockVault[]>("vaults", []);
    const vault = vaults.find((v) => v.id === doc.vaultId);
    if (vault && req.approvedBy.length >= vault.approvalThreshold) {
      req.status = 1; // Approved
    }
  }

  requests[reqIdx] = req;
  saveMockStorage("requests", requests);
};

const fetchPendingApprovalsForGuardian = async (
  guardianAddress: string
): Promise<StellarPendingApprovalData[]> => {
  const requests = getMockStorage<MockRequest[]>("requests", []);
  const docs = getMockStorage<MockDocument[]>("documents", []);
  const vaults = getMockStorage<MockVault[]>("vaults", []);
  const target = guardianAddress.toLowerCase();

  const pending: StellarPendingApprovalData[] = [];

  for (const req of requests) {
    if (req.status !== 0) continue; // Not pending
    if (req.approvedBy.some((a) => a.toLowerCase() === target)) continue; // Already approved by us

    const doc = docs.find((d) => d.id === req.documentId);
    if (!doc) continue;

    const vault = vaults.find((v) => v.id === doc.vaultId);
    if (!vault) continue;

    // Check if the user is a guardian of this vault
    const isGuardian = vault.guardians.some((g) => g.toLowerCase() === target);
    if (!isGuardian) continue;

    pending.push({
      requestId: req.requestId,
      documentId: req.documentId,
      vaultId: vault.id,
      vaultName: vault.name,
      requester: req.requester,
      createdAt: req.createdAt,
      expiresAt: req.expiresAt,
    });
  }

  return pending;
};

const getEncryptedGuardianShare = async (documentId: number, guardian: string): Promise<string> => {
  const docs = getMockStorage<MockDocument[]>("documents", []);
  const doc = docs.find((d) => d.id === documentId);
  return doc?.shares?.[guardian] || "";
};

const getBeneficiaryKeyShare = async (requestId: number, guardian: string): Promise<string> => {
  const requests = getMockStorage<MockRequest[]>("requests", []);
  const req = requests.find((r) => r.requestId === requestId);
  return req?.beneficiaryShares?.[guardian] || "";
};

const getPendingInvites = async (account: string): Promise<MockInvite[]> => {
  const invites = getMockStorage<MockInvite[]>("invites", []);
  const target = account.toLowerCase();
  return invites.filter((inv) => inv.guardian.toLowerCase() === target && !inv.accepted);
};

const acceptGuardianInvite = async (vaultId: number): Promise<void> => {
  if (!activeAccount) throw new Error("Wallet not connected");

  const invites = getMockStorage<MockInvite[]>("invites", []);
  const invIdx = invites.findIndex(
    (inv) => inv.vaultId === vaultId && inv.guardian.toLowerCase() === activeAccount!.toLowerCase()
  );

  if (invIdx !== -1) {
    invites[invIdx].accepted = true;
    saveMockStorage("invites", invites);
  }

  const vaults = getMockStorage<MockVault[]>("vaults", []);
  const vaultIdx = vaults.findIndex((v) => v.id === vaultId);
  if (vaultIdx !== -1) {
    if (!vaults[vaultIdx].guardians.includes(activeAccount)) {
      vaults[vaultIdx].guardians.push(activeAccount);
      saveMockStorage("vaults", vaults);
    }
  }
};

const registerPublicKey = async (publicKey: string): Promise<void> => {
  if (!activeAccount) throw new Error("Wallet not connected");
  const pubKeys = getMockStorage<Record<string, string>>("public_keys", {});
  pubKeys[activeAccount] = publicKey;
  saveMockStorage("public_keys", pubKeys);
};

const getUserPublicKey = async (user: string): Promise<string> => {
  const pubKeys = getMockStorage<Record<string, string>>("public_keys", {});
  return pubKeys[user] || "";
};

interface MockToken {
  tokenId: number;
  owner: string;
  vaultId: number;
  tokenURI: string;
  mintedAt: number;
}

const fetchUserTokens = async (account: string): Promise<StellarTokenData[]> => {
  if (!account) return [];
  const tokens = getMockStorage<MockToken[]>("tokens", []);
  const target = account.toLowerCase();
  return tokens
    .filter((t) => t.owner.toLowerCase() === target)
    .map((t) => ({
      tokenId: t.tokenId,
      owner: t.owner,
      vaultId: t.vaultId,
      tokenURI: t.tokenURI || "",
      mintedAt: t.mintedAt || null,
    }));
};

const hasVaultToken = async (account: string, vaultId: number): Promise<boolean> => {
  if (!account || !vaultId || vaultId <= 0) return false;
  try {
    const tokens = getMockStorage<MockToken[]>("tokens", []);
    const target = account.toLowerCase();
    const hasMockToken = tokens.some(
      (t) => t.vaultId === vaultId && t.owner.toLowerCase() === target
    );
    if (hasMockToken) return true;

    if (isConfigured()) {
      void sorobanRpcUrl;
    }
    return false;
  } catch (error) {
    console.error("Soroban token query failed:", error);
    return false;
  }
};

const mintAccessToken = async (
  vaultId: number,
  to: string,
  tokenURI: string
): Promise<number> => {
  const tokens = getMockStorage<MockToken[]>("tokens", []);
  const nextId = tokens.length + 1;
  const newToken: MockToken = {
    tokenId: nextId,
    owner: to,
    vaultId,
    tokenURI,
    mintedAt: Math.floor(Date.now() / 1000),
  };
  tokens.push(newToken);
  saveMockStorage("tokens", tokens);
  return nextId;
};

export const stellarService = {
  initialize,
  clear,
  getAccount,
  connectWallet,
  createVault,
  getVault,
  fetchVaultsForAccount,
  addDocument,
  fetchDocumentsForVaults,
  requestAccess,
  approveAccess,
  fetchPendingApprovalsForGuardian,
  getEncryptedGuardianShare,
  getBeneficiaryKeyShare,
  getPendingInvites,
  acceptGuardianInvite,
  registerPublicKey,
  getUserPublicKey,
  fetchUserTokens,
  hasVaultToken,
  mintAccessToken,
  isConfigured,
};
