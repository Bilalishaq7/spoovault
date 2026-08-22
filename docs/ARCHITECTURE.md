# SpooVault System Architecture

SpooVault is an enterprise-grade document custody and secret sharing application supporting dual-chain operation across **Avalanche (EVM)** and **Stellar (Soroban)** networks.

---

## 1. High-Level System Topology

```
+-----------------------------------------------------------------------------------+
|                                  SpooVault React DApp                             |
|    +-----------------------+   +------------------------+   +-------------------+ |
|    | Client-Side AES-256   |   | Shamir Secret Sharing  |   | TweetNaCl Box     | |
|    +-----------------------+   +------------------------+   +-------------------+ |
+------------------------------------------+----------------------------------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
                    v                                             v
     +------------------------------+             +-------------------------------+
     |   Avalanche C-Chain (EVM)    |             |    Stellar Network (Soroban)  |
     |   - SpooVault.sol            |             |    - SpooVault Soroban Contract|
     |   - Document Metadata Registry|             |    - Guardian Thresholds      |
     |   - Guardian Consensus Vaults|             |    - Key Release Requests     |
     |   - Access Pass NFTs         |             |                               |
     +------------------------------+             +-------------------------------+
                    |                                             |
                    +----------------------+----------------------+
                                           |
                                           v
                             +--------------------------+
                             |    Decentralized Storage |
                             |    - IPFS Gateway Proxy  |
                             |    - Encrypted Data CID   |
                             +--------------------------+
```

---

## 2. Cryptographic Security Model

1. **Zero-Knowledge Upload**: Documents are encrypted entirely client-side using AES-256-GCM prior to being dispatched to IPFS. Raw document payloads never touch server or blockchain memory unencrypted.
2. **Key Splitting via Shamir Secret Sharing (SSS)**: Master encryption keys are split into threshold shares \( (k, n) \). Shares are distributed securely to designated Guardian public keys via TweetNaCl public-key box encryption.
3. **Threshold Key Reconstruction**: Beneficiaries initiate document release requests. Guardians independently review and approve requests on-chain. Once the required threshold \( k \) of \( n \) signatures is met, encrypted key packages are released for client-side assembly and document decryption.
4. **No Self-Approval Invariant**: An access approval can never originate from the request's beneficiary. `_approveAccess` reverts with `CannotSelfApproveAccess` when `msg.sender == request.requester`, so quorum counts only distinct, accepted guardians other than the requester. This holds even when the requester later becomes a guardian (e.g. a request filed before accepting a guardian invite), preventing any self-vote from inflating multi-sig quorum in multi-custody or emergency inheritance configurations.

---

## 3. Dual-Chain Smart Contract Layer

### Avalanche (Solidity `SpooVault.sol`)
- Manages document metadata records, vault configurations, guardian thresholds, and NFT access pass minting on Avalanche Fuji testnet (Chain ID `43113`).

### Stellar (Soroban Rust Contract)
- Manages document registry, guardian approvals, and key inbox distribution on the Stellar Soroban testnet using native Rust Soroban SDK data structures.

---

## 4. IPFS Storage, Gateway Pool & Circuit Breaker

To prevent client-side leaks of Pinata API credentials:
- Production pin requests route through `scripts/pinata-proxy.mjs`. The Pinata JWT stays on the server.
- CORS is restricted to `SPOOVUALT_ALLOWED_ORIGINS` (local Vite URLs by default). Wildcard `Access-Control-Allow-Origin: *` is not used.
- Every `/api/ipfs/*` pin or list call must present `X-SpooVault-Signature: t=<unix>,v1=<hmac-sha256-hex>`. The HMAC covers timestamp, method, path, and body hash. Unsigned or cross-origin callers receive **403 Forbidden**.
- The frontend signs with `VITE_SPOOVUALT_PROXY_SECRET` (a dedicated HMAC key, not the Pinata JWT). See `scripts/lib/ipfsProxyGuard.mjs`.

Document **downloads** no longer depend on a single Pinata URL. `src/services/ipfsGateway.ts` races a public gateway pool and fails over automatically when the primary gateway rate-limits or stalls:

1. Pinata (`VITE_IPFS_GATEWAY`, default `https://gateway.pinata.cloud/ipfs/`)
2. Infura IPFS (`https://ipfs.infura.io/ipfs/`)
3. Cloudflare IPFS (`https://cloudflare-ipfs.com/ipfs/`)
4. IPFS.io (`https://ipfs.io/ipfs/`)

Each gateway has a circuit breaker. HTTP 429, timeouts, 401/403, and 5xx responses open that gateway's circuit for 30 seconds so a rate-limited Pinata endpoint is skipped on the next fetch. Healthy (or half-open) gateways are raced in parallel; the first 2xx wins and remaining in-flight requests are aborted.

Callers use `ipfsService.fetchFile` / `fetchFromIPFS` (Documents, Access Center, and NFT `ipfs://` metadata). `getIPFSURL` remains a deterministic primary-gateway URL for display and copy. Extra download gateways can be appended with `VITE_IPFS_FALLBACK_GATEWAYS`.

---

## 5. Private Information Retrieval (PIR)

To prevent IPFS gateway surveillance (where gateways log requester IP addresses and requested CIDs, allowing correlation of beneficiary identities with specific vault documents), SpooVault implements Private Information Retrieval (PIR) principles:

### PIR Components (`src/services/pir.service.ts`)

1. **HomomorphicHash**: Generates deterministic but non-reversible CID identifiers using SHA-256 with per-session salt. Same CID produces same hash within a session, but different sessions produce different hashes, preventing gateway operators from identifying specific documents from logged hashes.

2. **DummyQueryBatcher**: Generates dummy IPFS queries that look like real CIDs (CIDv0 format) and batches real queries with dummy queries to obscure which document is being fetched. The batch is shuffled to prevent position-based analysis. Configurable dummy query count (default: 5) and batch delay (default: 100ms).

3. **TorProxyClient**: SOCKS5 proxy client for routing IPFS requests through Tor, providing IP address anonymity when fetching documents. Requires local Tor daemon with SOCKS5 proxy enabled (default: 127.0.0.1:9050). Falls back to standard fetch if Tor is unavailable.

### PIR Integration

The PIR service integrates with the existing IPFS gateway infrastructure:
- `ipfsService.fetchFileWithPIR()`: New method that uses PIR for document fetches
- Falls back to standard `ipfsGateway.fetchFile()` if PIR is disabled
- Maintains compatibility with existing multi-gateway circuit breaker
- Works with existing gateway pool and health scoring system

### Configuration

PIR is configured via environment variables (see `.env.example`):
- `VITE_PIR_ENABLED`: Enable PIR to obscure which documents are being fetched
- `VITE_PIR_USE_TOR`: Use Tor SOCKS5 proxy for IPFS fetches
- `VITE_PIR_TOR_HOST`: Tor SOCKS5 proxy host (default: 127.0.0.1)
- `VITE_PIR_TOR_PORT`: Tor SOCKS5 proxy port (default: 9050)
- `VITE_PIR_DUMMY_COUNT`: Number of dummy queries to batch with real queries (default: 5)
- `VITE_PIR_BATCH_DELAY`: Delay between dummy queries in milliseconds (default: 100)

### Security Properties

- **Oblivious Gateway Querying**: Real queries are batched with dummy queries, making it statistically difficult for gateways to identify which query corresponds to the actual document
- **Mixnet Proxy Routing**: When enabled, all IPFS requests are routed through Tor's SOCKS5 proxy for IP address anonymity
- **Encrypted CID Index**: CIDs are hashed with session-specific salts before logging, making hashes non-reversible

See `docs/PIR_ARCHITECTURE.md` for detailed PIR architecture and usage documentation.

---

## 6. Read-Call Caching

`contract.service.ts` caches the results of read-only view calls (`hasActiveAccess`, `getVault`) for a 10-second TTL, keyed by their arguments (document/vault/user), with concurrent duplicate calls deduped into a single underlying request. This avoids re-issuing the same RPC call on every page navigation or component remount. Write actions that change cached state (e.g. `approveAccess`, `acceptGuardianInvite`, `burnAccessToken`) invalidate the relevant cache entries immediately, and `contractService.clear()` resets the cache on wallet disconnect. See `src/utils/ttlCache.ts` for the generic cache implementation.

The Stellar/Soroban path currently has no real RPC calls (reads are `localStorage`-backed mocks pending real Soroban integration — see the `// TODO (Contributor)` markers in `stellar.service.ts`), so this caching layer reduces real RPC volume only on the Avalanche path today. It is wired at the ecosystem-agnostic `proxied*` layer so it applies automatically once real Soroban reads are implemented.

---

## 7. Windowed List Rendering (Document & Access Pass Lists)

`Documents.tsx` and `NFTGallery.tsx` render potentially large lists (uploaded documents, minted access passes) that previously mounted every item to the DOM unconditionally, causing scroll jank as a vault's item count grows.

Both pages now delegate their list rendering to a dedicated, presentational component that windows the DOM using [`@tanstack/react-virtual`](https://tanstack.com/virtual/latest):

- `src/components/documents/VirtualizedDocumentsList.tsx` — windows the document table body. The table markup itself is a CSS-grid of `role="table"/"row"/"cell"` divs rather than a native `<table>`, because native table rows can't be absolutely positioned for windowing without breaking column alignment (see decision rationale in PR #45).
- `src/components/nft/VirtualizedNftGrid.tsx` — windows the access-pass card grid by chunking tokens into rows matching the current responsive column count (1/2/3 columns) and virtualizing rows of cards.

Both components use `useVirtualizer`'s `measureElement` for dynamic per-row sizing (rather than a single fixed row height), since row/card content height varies with wrapped text and action-button counts. Only rows within the viewport plus a small overscan are ever mounted to the DOM, regardless of total list length.

`@tanstack/react-virtual` was already present in `package-lock.json` as a transitive dependency of `@heroui/react`'s internal `Table`/`Listbox` virtualization (HeroUI's own `<Table isVirtualized>` uses it internally) — it is now also a direct dependency, pinned to the same locked version, since both pages call it directly.
