// Signature-Login: Cross-platform cryptographic login/verify module
import * as secp from "@noble/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2";
import { generateAccountIdentifier } from './username.js';

// Set up HMAC for secp256k1
secp.etc.hmacSha256Sync = (key, ...msgs) => hmac(nobleSha256, key, secp.etc.concatBytes(...msgs));

// Browser compatibility helper for TextEncoder
async function getTextEncoder() {
  if (typeof window !== "undefined") {
    return new window.TextEncoder();
  } else {
    // Dynamic import for Node.js only
    const util = await import("node:util");
    return new util.TextEncoder();
  }
}

// Helper function to convert bytes to hex
function bytesToHex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Helper function to convert hex to bytes
function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// Helper function to generate random bytes
async function randomBytes(length) {
  if (typeof window !== "undefined" && window.crypto) {
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
    return bytes;
  } else {
    // Dynamic import for Node.js only
    const crypto = await import("node:crypto");
    return new Uint8Array(crypto.randomBytes(length));
  }
}

// --- Base64 Encoding/Decoding Helpers ---
// Browser-safe base64 encode
function base64Encode(obj) {
  const json = JSON.stringify(obj);
  if (typeof window !== "undefined") {
    return btoa(json);
  } else {
    return Buffer.from(json).toString('base64');
  }
}

// Browser-safe base64 decode
function base64Decode(str) {
  if (typeof window !== "undefined") {
    return JSON.parse(atob(str));
  } else {
    return JSON.parse(Buffer.from(str, 'base64').toString());
  }
}

// --- Key Generation ---
export function generateKeyPair() {
  const privateKey = secp.utils.randomPrivateKey();
  const publicKey = secp.getPublicKey(privateKey, true);

  return {
    privateKey: bytesToHex(privateKey),
    publicKey: bytesToHex(publicKey),
  };
}

// --- Get Public Key from Private Key ---
export function getPublicKey(privateKeyHex) {
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const publicKeyBytes = secp.getPublicKey(privateKeyBytes, true); // compressed
  return bytesToHex(publicKeyBytes);
}

// --- Account Username from Public Key ---
export async function getUsername(publicKey) {
  return await generateAccountIdentifier(publicKey);
}

// --- Hashing (SHA-256) ---
export async function sha256(msg) {
  const encoder = await getTextEncoder();
  const encoded = encoder.encode(msg);

  if (typeof window === "undefined") {
    // Node.js - dynamic import
    const crypto = await import("node:crypto");
    return new Uint8Array(crypto.createHash("sha256").update(encoded).digest());
  } else {
    // Browser
    const hash = await window.crypto.subtle.digest("SHA-256", encoded);
    return new Uint8Array(hash);
  }
}

// --- Proof of Work Helper ---
async function solveProofOfWork(message, difficulty = 2) {
  if (difficulty < 1) {
    difficulty = 1; // Minimum POW is 1
  }

  const target = '0'.repeat(difficulty);
  let nonce = 0;

  while (true) {
    const combined = message + nonce;
    const hash = await sha256(combined);
    const hexHash = bytesToHex(hash);

    if (hexHash.startsWith(target)) {
      return nonce;
    }
    nonce++;

    // Yield to event loop every 1000 attempts to avoid blocking
    if (nonce % 1000 === 0) {
      await new Promise(resolve => setTimeout(resolve, 0));
    }
  }
}

// --- Verify Proof of Work ---
async function verifyProofOfWork(message, powNonce, difficulty = 2) {
  if (difficulty < 1) {
    difficulty = 1; // Minimum POW is 1
  }

  if (powNonce === null || powNonce === undefined) {
    return false;
  }

  const target = '0'.repeat(difficulty);
  const combined = message + powNonce;
  const hash = await sha256(combined);
  const hexHash = bytesToHex(hash);

  return hexHash.startsWith(target);
}

// --- Sign Message ---
export async function sign(message, privateKeyHex, pow = 2) {
  // Enforce minimum POW of 1
  if (pow < 1) {
    pow = 1;
  }

  const hash = await sha256(message);
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const sig = secp.sign(hash, privateKeyBytes);
  const signature = bytesToHex(sig.toCompactRawBytes());

  // Always generate POW and return object format
  const powNonce = await solveProofOfWork(message, pow);
  return { signature, pow: powNonce };
}

// --- Verify Signature ---
export async function verify(message, signatureData, publicKeyHex, pow = 2) {
  try {
    // Enforce minimum POW of 1
    if (pow < 1) {
      pow = 1;
    }

    // Always expect object format { signature, pow }
    const signatureHex = signatureData.signature;
    const powNonce = signatureData.pow;

    if (!signatureHex || powNonce === undefined || powNonce === null) {
      return false;
    }

    // Verify POW
    const powValid = await verifyProofOfWork(message, powNonce, pow);
    if (!powValid) {
      return false;
    }

    // Verify signature
    const hash = await sha256(message);
    const signatureBytes = hexToBytes(signatureHex);
    const publicKeyBytes = hexToBytes(publicKeyHex);
    return secp.verify(signatureBytes, hash, publicKeyBytes);
  } catch {
    return false;
  }
}

// --- Auth Header Helper ---
export async function createAuth(privateKeyHex, pow = 2) {
  // Enforce minimum POW of 1
  if (pow < 1) {
    pow = 1;
  }

  const publicKeyHex = getPublicKey(privateKeyHex);

  const timestamp = Date.now();
  const nonceBytes = await randomBytes(16);
  const nonce = bytesToHex(nonceBytes);
  const message = `${timestamp}:${nonce}`;

  const signatureData = await sign(message, privateKeyHex, pow);

  const authPayload = {
    publickey: publicKeyHex,
    signature: signatureData.signature,
    pow: signatureData.pow,
    message,
    timestamp,
    nonce
  };

  return base64Encode(authPayload);
}

// --- Verify Auth Token ---
export async function verifyAuth(token, pow = 2) {
  try {
    // Enforce minimum POW of 1
    if (pow < 1) {
      pow = 1;
    }

    // Decode token
    const authData = base64Decode(token);
    const publicKeyHex = authData.publickey;
    const { signature, message, pow: powNonce } = authData;

    if (!publicKeyHex || !signature || !message || powNonce === undefined || powNonce === null) {
      return null;
    }

    // Extract timestamp from message
    const timestamp = Number(message.split(':')[0]);

    // Check timestamp is within 1 minute
    const maxAgeMs = 1 * 60 * 1000; // Hardcoded to 1 minute
    const now = Date.now();
    if (isNaN(timestamp) || Math.abs(now - timestamp) > maxAgeMs) {
      return null;
    }

    // Verify signature and POW
    const signatureData = { signature, pow: powNonce };
    const isValid = await verify(message, signatureData, publicKeyHex, pow);
    if (!isValid) {
      return null;
    }

    return publicKeyHex;

  } catch {
    return null;
  }
}
