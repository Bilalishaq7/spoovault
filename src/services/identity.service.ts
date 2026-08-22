export interface IdentityBinding {
  evmAddress: string;
  stellarAddress: string;
  registeredAt: number;
}

const STORAGE_KEY = "spoovault-crosschain-identity-registry";

export const isValidEVMAddress = (address: string): boolean => {
  if (!address || typeof address !== "string") return false;
  return /^0x[a-fA-F0-9]{40}$/.test(address.trim());
};

export const isValidStellarAddress = (address: string): boolean => {
  if (!address || typeof address !== "string") return false;
  return /^G[A-Z2-7]{55}$/.test(address.trim());
};

export const isValidMultiChainAddress = (address: string): boolean => {
  return isValidEVMAddress(address) || isValidStellarAddress(address);
};

const loadRegistry = (): IdentityBinding[] => {
  if (typeof localStorage === "undefined") return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? (JSON.parse(raw) as IdentityBinding[]) : [];
  } catch {
    return [];
  }
};

const saveRegistry = (bindings: IdentityBinding[]): void => {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(bindings));
  } catch {
    // ignore storage write errors
  }
};

const registerIdentity = async (
  evmAddress: string,
  stellarAddress: string
): Promise<IdentityBinding> => {
  const cleanEvm = (evmAddress || "").trim();
  const cleanStellar = (stellarAddress || "").trim();

  if (!isValidEVMAddress(cleanEvm)) {
    throw new Error("Invalid EVM address format. Must start with 0x followed by 40 hex characters.");
  }
  if (!isValidStellarAddress(cleanStellar)) {
    throw new Error("Invalid Stellar address format. Must start with G followed by 55 base32 characters.");
  }

  const registry = loadRegistry();
  const evmLower = cleanEvm.toLowerCase();

  // Check for conflicting registrations
  const existingEvmMatch = registry.find(
    (b) => b.evmAddress.toLowerCase() === evmLower
  );
  if (existingEvmMatch && existingEvmMatch.stellarAddress !== cleanStellar) {
    throw new Error(`EVM address ${cleanEvm.slice(0, 6)}... is already linked to a different Stellar address.`);
  }

  const existingStellarMatch = registry.find(
    (b) => b.stellarAddress === cleanStellar
  );
  if (existingStellarMatch && existingStellarMatch.evmAddress.toLowerCase() !== evmLower) {
    throw new Error(`Stellar address ${cleanStellar.slice(0, 6)}... is already linked to a different EVM address.`);
  }

  if (existingEvmMatch && existingStellarMatch) {
    return existingEvmMatch;
  }

  const newBinding: IdentityBinding = {
    evmAddress: cleanEvm,
    stellarAddress: cleanStellar,
    registeredAt: Math.floor(Date.now() / 1000),
  };

  registry.push(newBinding);
  saveRegistry(registry);
  return newBinding;
};

const resolveStellarAddress = async (addressInput: string): Promise<string | null> => {
  const clean = (addressInput || "").trim();
  if (!clean) return null;

  if (isValidStellarAddress(clean)) {
    return clean;
  }

  if (!isValidEVMAddress(clean)) {
    return null;
  }

  const registry = loadRegistry();
  const matched = registry.find((b) => b.evmAddress.toLowerCase() === clean.toLowerCase());
  return matched ? matched.stellarAddress : null;
};

const resolveEVMAddress = async (addressInput: string): Promise<string | null> => {
  const clean = (addressInput || "").trim();
  if (!clean) return null;

  if (isValidEVMAddress(clean)) {
    return clean;
  }

  if (!isValidStellarAddress(clean)) {
    return null;
  }

  const registry = loadRegistry();
  const matched = registry.find((b) => b.stellarAddress === clean);
  return matched ? matched.evmAddress : null;
};

const resolveAddressForNetwork = async (
  inputAddress: string,
  targetNetwork: "avalanche" | "stellar"
): Promise<string> => {
  const clean = (inputAddress || "").trim();
  if (!clean) {
    throw new Error("Address input cannot be empty.");
  }

  if (targetNetwork === "stellar") {
    const resolved = await resolveStellarAddress(clean);
    if (!resolved) {
      throw new Error(`Address ${clean.slice(0, 8)}... is not registered to a linked Stellar identity. Please bind on Profile page.`);
    }
    return resolved;
  } else if (targetNetwork === "avalanche") {
    const resolved = await resolveEVMAddress(clean);
    if (!resolved) {
      throw new Error(`Address ${clean.slice(0, 8)}... is not registered to a linked Avalanche EVM identity. Please bind on Profile page.`);
    }
    return resolved;
  }

  return clean;
};

const getRegisteredIdentities = (): IdentityBinding[] => {
  return loadRegistry();
};

const clear = (): void => {
  if (typeof localStorage !== "undefined") {
    localStorage.removeItem(STORAGE_KEY);
  }
};

export const identityService = {
  isValidEVMAddress,
  isValidStellarAddress,
  isValidMultiChainAddress,
  registerIdentity,
  resolveStellarAddress,
  resolveEVMAddress,
  resolveAddressForNetwork,
  getRegisteredIdentities,
  clear,
};
