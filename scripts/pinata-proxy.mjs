/**
 * Pinata IPFS Proxy Server
 *
 * A lightweight Express proxy that forwards IPFS pin/fetch requests to Pinata
 * while keeping the API credentials server-side.
 *
 * Usage (local dev):
 *   PINATA_JWT=your_jwt node scripts/pinata-proxy.mjs
 *   or
 *   PINATA_API_KEY=x PINATA_API_SECRET=y node scripts/pinata-proxy.mjs
 *
 * Endpoints:
 *   POST /api/ipfs/pin-file   - Pin a file to IPFS (multipart/form-data with "file" field)
 *   POST /api/ipfs/pin-json   - Pin a JSON object to IPFS (application/json body)
 *   GET  /api/ipfs/pin-list   - List pinned files
 *
 * For production:
 *   Deploy this file to a Cloud Run, Render, Railway, or similar service.
 *   Then set VITE_IPFS_PROXY_URL=https://your-proxy.example.com in frontend .env
 *
 * Note: For Firebase Functions deployment, see:
 *   functions/index.js (created separately)
 */

import { Readable } from "node:stream";

// Check for required dependencies
let express, cors;
try {
  const expressModule = await import("express");
  express = expressModule.default;
} catch {
  console.error(
    "❌ 'express' is not installed. Run:\n   npm install --save-dev express cors\n"
  );
  process.exit(1);
}
try {
  const corsModule = await import("cors");
  cors = corsModule.default;
} catch {
  console.error(
    "❌ 'cors' is not installed. Run:\n   npm install --save-dev cors\n"
  );
  process.exit(1);
}

const PINATA_JWT = process.env.PINATA_JWT || process.env.VITE_PINATA_JWT || "";
const PINATA_API_KEY = process.env.PINATA_API_KEY || process.env.VITE_PINATA_API_KEY || "";
const PINATA_API_SECRET = process.env.PINATA_API_SECRET || process.env.VITE_PINATA_API_SECRET || "";
const PORT = Number(process.env.PORT) || 3001;

if (!PINATA_JWT && !(PINATA_API_KEY && PINATA_API_SECRET)) {
  console.error(
    "❌ Pinata credentials not found.\n" +
    "   Set PINATA_JWT (recommended) or PINATA_API_KEY + PINATA_API_SECRET environment variables.\n"
  );
  process.exit(1);
}

const buildPinataHeaders = (includeContentType = false) => {
  const headers = {};
  if (PINATA_JWT) {
    headers["Authorization"] = `Bearer ${PINATA_JWT}`;
  } else {
    headers["pinata_api_key"] = PINATA_API_KEY;
    headers["pinata_secret_api_key"] = PINATA_API_SECRET;
  }
  if (includeContentType) {
    headers["Content-Type"] = "application/json";
  }
  return headers;
};

const app = express();
app.use(cors({ origin: "*" }));

/**
 * POST /api/ipfs/pin-file
 *
 * Transparent multipart passthrough to Pinata so multi-GB streaming uploads
 * are never buffered in proxy memory (unlike multer.memoryStorage).
 */
app.post("/api/ipfs/pin-file", async (req, res) => {
  try {
    const contentType = req.headers["content-type"];
    if (!contentType || !String(contentType).includes("multipart/form-data")) {
      return res.status(400).json({
        error: 'Expected multipart/form-data with a "file" field',
      });
    }

    const headers = buildPinataHeaders();
    headers["content-type"] = contentType;
    if (req.headers["content-length"]) {
      headers["content-length"] = req.headers["content-length"];
    }

    const response = await globalThis.fetch(
      "https://api.pinata.cloud/pinning/pinFileToIPFS",
      {
        method: "POST",
        headers,
        body: Readable.toWeb(req),
        duplex: "half",
      }
    );

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json(data);
    }
    return res.json(data);
  } catch (err) {
    console.error("pin-file error:", err);
    return res.status(500).json({ error: err.message || "Internal server error" });
  }
});

/**
 * POST /api/ipfs/pin-json
 * Accepts JSON body with:
 *   - pinataContent: the object to pin
 *   - pinataMetadata (optional): {name, keyvalues}
 */
app.post("/api/ipfs/pin-json", express.json({ limit: "50mb" }), async (req, res) => {
  try {
    const { pinataContent, pinataMetadata, pinataOptions } = req.body;
    if (!pinataContent) {
      return res.status(400).json({ error: "pinataContent is required" });
    }

    const body = JSON.stringify({ pinataContent, pinataMetadata, pinataOptions });
    const response = await globalThis.fetch(
      "https://api.pinata.cloud/pinning/pinJSONToIPFS",
      { method: "POST", headers: buildPinataHeaders(true), body }
    );

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json(data);
    }
    return res.json(data);
  } catch (err) {
    console.error("pin-json error:", err);
    return res.status(500).json({ error: err.message || "Internal server error" });
  }
});

/**
 * GET /api/ipfs/pin-list
 * Returns a list of pins from the Pinata account.
 */
app.get("/api/ipfs/pin-list", async (req, res) => {
  try {
    const queryParams = new URLSearchParams();
    if (req.query.status) queryParams.set("status", String(req.query.status));
    if (req.query.pageLimit) queryParams.set("pageLimit", String(req.query.pageLimit));
    if (req.query.pageOffset) queryParams.set("pageOffset", String(req.query.pageOffset));

    const url = `https://api.pinata.cloud/data/pinList?${queryParams.toString()}`;
    const response = await globalThis.fetch(url, {
      method: "GET",
      headers: buildPinataHeaders(),
    });

    const data = await response.json();
    if (!response.ok) {
      return res.status(response.status).json(data);
    }
    return res.json(data);
  } catch (err) {
    console.error("pin-list error:", err);
    return res.status(500).json({ error: err.message || "Internal server error" });
  }
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`\n✅ Pinata proxy running at http://localhost:${PORT}`);
  console.log("   Endpoints:");
  console.log("   POST /api/ipfs/pin-file (streaming passthrough)");
  console.log("   POST /api/ipfs/pin-json");
  console.log("   GET  /api/ipfs/pin-list");
  console.log("   GET  /health\n");
});
