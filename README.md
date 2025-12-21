# DAKU

> Leave no trace. Just authenticate.

DAKU (spelled DAA KU) — Punjabi for "bandits" — inspired the library's name. Historically, bandits operated anonymously and often used masks to hide their identity; this project adopts that privacy-first ethos by offering anonymous, cryptographic authentication without personal data.

DAKU is a lightweight cryptographic authentication library that provides built-in proof-of-work (POW) spam protection. It requires no emails, no passwords, and no personally identifiable information — instead users authenticate with a secp256k1 keypair (a privateKey and a derived publicKey). Auth tokens include a timestamp, nonce, signature, and POW, and expire by default after 1 minute.

## Global Identity — One Private Key, Multiple Projects

You can reuse a single DAKU privateKey across multiple projects to act as a global unique identifier. Since the publicKey is deterministically derived from the privateKey, the same publicKey serves as a consistent user fingerprint across different apps and services. This approach lets you:

- Enable cross-project authentication without separate accounts or PII
- Maintain portability and a consistent user identity across apps

Important: reusing the same privateKey links your identity between services, which may be desirable (single identity) or undesired (linkability). Keep your privateKey secure — store it safely (e.g., secure storage or hardware wallet) and never share it publicly. If you need per-app separation, generate or derive app-specific keys instead.

Security notes: Tokens are short-lived and POW difficulty is configurable (default: 2 leading zeros) to reduce abuse; adjust as needed for your application.

## Installation

```bash
npm install daku
```

## Quick Start

### 1. Generate a Keypair

```javascript
import { generateKeyPair } from "daku";

// Generate once and store securely (localStorage, secure storage, etc.)
const { privateKey, publicKey } = generateKeyPair();
```

### 2. Client-Side: Create Authentication Request

```javascript
import { createAuth } from "daku";

// Create authentication token (includes timestamp, nonce, signature, and POW)
const token = await createAuth(privateKey);

// Send to your server
fetch("/api/login", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    daku: token,
  },
});
```

### 3. Server-Side: Verify Authentication

```javascript
import { verifyAuth } from "daku";

const publicKey = await verifyAuth(req.headers["daku"]);

if (publicKey) {
  // ✅ Authenticated! Use publicKey as unique user ID
  console.log(`User ${publicKey} authenticated`);
} else {
  // ❌ Invalid or expired authentication
  res.status(401).json({ error: "Unauthorized" });
}
```

## ExpressJS Middleware

```javascript
import express from "express";
import { verifyAuth } from "daku";

const app = express();

// Reusable authentication middleware
const daku = (powDifficulty = 2) => {
  return async (req, res, next) => {
    const token = req.headers["daku"];

    if (!token) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const publicKey = await verifyAuth(token, powDifficulty);

    if (!publicKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Attach user's public key to request
    req.userId = publicKey;
    next();
  };
};

// Use on protected routes
app.post("/api/protected", daku(), (req, res) => {
  res.json({
    message: "Access granted",
    userId: req.userId,
  });
});

// Use with custom POW difficulty
app.post("/api/high-security", daku(4), (req, res) => {
  res.json({ message: "High security endpoint" });
});

app.listen(3000);
```

## Key Features

- **🕵️ Anonymous**: No email, phone, or personal data required
- **🛡️ Spam Protection**: Built-in proof-of-work (default: 2 leading zeros)
- **🔐 Secure**: secp256k1 cryptographic signatures (same as Bitcoin/Ethereum)
- **⚡ Lightweight**: Minimal dependencies (@noble/secp256k1, @noble/hashes)
- **🌐 Cross-Platform**: Works in Node.js and browsers
- **⏱️ Time-Limited**: Auth requests expire after 1 minute

## API Reference

```javascript
// Quick exports summary — simple overview of what the library exposes
import {
  createAuth, // createAuth(privateKey, pow = 2) -> string (base64 auth token)
  verifyAuth, // verifyAuth(token, pow = 2) -> publicKey string | null
  sign, // sign(message, privateKey, pow = 2) -> { signature, pow }
  verify, // verify(message, signatureData, publicKey, pow = 2) -> boolean
  generateKeyPair, // generateKeyPair() -> { privateKey, publicKey }
  getPublicKey, // getPublicKey(privateKey) -> publicKey string
  getUsername, // getUsername(publicKey) -> human-readable username string
  sha256, // sha256(message) -> Uint8Array
} from "daku";

// Example: create and verify a simple auth token
const { privateKey } = generateKeyPair();
const token = await createAuth(privateKey);
const publicKey = await verifyAuth(token);
```

### getUsername - Convert Public Key to Human-Readable Username

Since public keys are long hexadecimal strings (like `03a1b2c3...`), they're not user-friendly for display. The `getUsername()` function converts any public key into a memorable, readable username.

```javascript
import { getUsername, generateKeyPair } from "daku";

const { publicKey } = generateKeyPair();
const username = await getUsername(publicKey);
// Returns something like: "happy-ocean-flows-1234"
```

**How it works:**
- Takes a public key as input
- Uses SHA-256 hash to deterministically generate a username
- Same public key **always** produces the same username
- Format: `adjective-noun-verb-number` (e.g., "brave-tiger-soars-4567")

**Why use it:**
- Display usernames in your UI instead of long hex strings
- Create consistent, recognizable identities for users
- No database needed - the username is derived from the public key itself

> [!IMPORTANT]
> **DAKU is designed to keep users anonymous.** You should **never ask users to create a username**. Let `getUsername()` automatically generate one from their public key and display it in your UI. Since you identify users by their public key (not username), it doesn't matter if two users happen to have the same username - each public key is cryptographically unique.

> [!IMPORTANT]
> **Never store usernames in your database.** Since the same public key always generates the same username, you can regenerate it on-the-fly by calling `getUsername(publicKey)` whenever needed. Store only the public key as your user identifier.

**Example in a real app:**
```javascript
app.post("/api/protected", daku(), async (req, res) => {
  const username = await getUsername(req.userId);
  res.json({
    message: `Welcome, ${username}!`,
    userId: req.userId, // Always use publicKey as unique ID, not username
  });
});
```
