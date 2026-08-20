import CryptoJS from "crypto-js";
import { ipfsService } from "../services/ipfs.service";

/**
 * Shorten Ethereum address
 */
export const shortenAddress = (address: string, chars = 4): string => {
  if (!address || address.length < chars * 2 + 2) return address || "";
  return `${address.substring(0, chars + 2)}...${address.substring(
    address.length - chars
  )}`;
};

/**
 * Generate a random encryption key
 */
export const generateEncryptionKey = (): string => {
  const array = new Uint8Array(32);
  window.crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join("");
};

/**
 * Encrypt data using AES-256
 */
export const encryptData = (data: string, key: string): string => {
  return CryptoJS.AES.encrypt(data, key).toString();
};

/**
 * Decrypt data using AES-256
 */
export const decryptData = (encryptedData: string, key: string): string => {
  const bytes = CryptoJS.AES.decrypt(encryptedData, key);
  return bytes.toString(CryptoJS.enc.Utf8);
};

/**
 * Upload file to IPFS (wrapper for ipfsService)
 */
export const uploadToIPFS = async (
  file: File,
  metadata: any = {},
  signal?: AbortSignal
): Promise<{ hash: string; size: number }> => {
  return ipfsService.uploadFile(file, metadata, signal);
};

/**
 * Format file size
 */
export const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

/**
 * Format date
 */
export const formatDate = (timestamp: number): string => {
  return new Date(timestamp * 1000).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
};

/**
 * Validate EVM address format (0x...)
 */
export const isValidEVMAddress = (address: string): boolean => {
  if (!address || typeof address !== "string") return false;
  return /^0x[a-fA-F0-9]{40}$/.test(address.trim());
};

/**
 * Validate Stellar address format (G...)
 */
export const isValidStellarAddress = (address: string): boolean => {
  if (!address || typeof address !== "string") return false;
  return /^G[A-Z2-7]{55}$/.test(address.trim());
};

/**
 * Validate address format on either EVM or Stellar networks
 */
export const isValidMultiChainAddress = (address: string): boolean => {
  return isValidEVMAddress(address) || isValidStellarAddress(address);
};

/**
 * Validate address (supports both EVM and Stellar format)
 */
export const isValidAddress = (address: string): boolean => {
  return isValidMultiChainAddress(address);
};

/**
 * Get IPFS gateway URL
 */
export const getIPFSURL = (hash: string): string => {
  return ipfsService.getURL(hash);
};

/**
 * Split encryption key among guardians (simplified)
 */
export const splitKeyAmongGuardians = (key: string, guardians: string[]): string[] => {
  // Note: In production, use Shamir's Secret Sharing
  const parts: string[] = [];
  const keyLength = key.length;
  const partSize = Math.ceil(keyLength / guardians.length);
  
  for (let i = 0; i < guardians.length; i++) {
    const start = i * partSize;
    const end = Math.min(start + partSize, keyLength);
    parts.push(key.slice(start, end));
  }
  
  return parts;
};

/**
 * Reconstruct key from guardian parts
 */
export const reconstructKey = (parts: string[]): string => {
  return parts.join("");
};

/**
 * Generate a unique request ID
 */
export const generateRequestId = (): string => {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
};

/**
 * Get current year for footer
 */
export const getCurrentYear = (): number => {
  return new Date().getFullYear();
};

/**
 * Check if IPFS is configured
 */
export const isIPFSConfigured = (): boolean => {
  return ipfsService.isConfigured();
};


