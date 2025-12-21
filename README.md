# DAKU

> **Anonymous authentication. Zero personal data.**

**DAKU** (pronounced _DAA KU_) means "bandits" in Punjabi. Historically, bandits operated anonymously, often using masks to hide their identity. This library adopts that privacy-first ethos—anonymous cryptographic authentication without personal data.

---

## Why DAKU?

**Stop storing passwords. Stop managing email verifications. Stop worrying about data breaches.**

DAKU is a simpler approach to user authentication that keeps both you and your users anonymous. No databases of usernames, no password hashes to secure, no personal information to leak.

```javascript
// Traditional auth: Store emails, hash passwords, manage resets...
// DAKU: Just verify cryptographic signatures ✨
const publicKey = await verifyAuth(token);
```

### The Problem with Traditional Auth

Every traditional authentication system carries risk:

- **Passwords**: Users reuse them, forget them, get them stolen
- **Email/Phone**: Requires collecting personal data (GDPR, privacy laws)
- **Databases**: Honeypots for hackers; one breach exposes everything
- **Identity**: Your users leave traces everywhere they sign up

### The DAKU Way

Users authenticate with cryptographic keypairs—like Bitcoin wallets, but for your app:

- **No signup forms**: Generate a keypair, start using your app
- **No passwords**: Users never create or remember passwords
- **No PII collection**: No emails, phones, or personal data
- **Built-in spam protection**: Proof-of-work prevents abuse
- **You stay clean**: Nothing sensitive to store, nothing to breach

> DAKU uses **secp256k1** signatures (same as Bitcoin/Ethereum) with **proof-of-work** spam protection. Auth tokens expire in 1 minute. Users control their private keys, you just verify signatures.

---

## Installation

```bash
npm install daku
```

## Quick Start

```javascript
import { generateKeyPair, createAuth, verifyAuth } from "daku";

// 1. User generates keypair (client-side)
const { privateKey, publicKey } = generateKeyPair();

// 2. Create auth token (client-side)
const token = await createAuth(privateKey);

// 3. Verify auth (server-side)
const publicKey = await verifyAuth(token);
// ✅ Authenticated! publicKey is the unique user ID
```

---

## Core Functions

### `generateKeyPair()`

**Create a new identity**

```javascript
const { privateKey, publicKey } = generateKeyPair();
```

Generates a secp256k1 keypair. The **privateKey** stays with the user (never share it), the **publicKey** identifies them to your service.

- Returns: `{ privateKey: string, publicKey: string }`
- Use case: First-time users, account creation

---

### `getPublicKey(privateKey)`

**Derive the public identity**

```javascript
const publicKey = getPublicKey(privateKey);
```

Extract the public key from a private key. Useful when users return with their saved privateKey.

- Returns: `publicKey` string
- Deterministic: Same privateKey always produces same publicKey

---

### `getUsername(publicKey)`

**Make public keys human-readable**

```javascript
const username = await getUsername(publicKey);
// → "happy-ocean-flows-1234"
```

Public keys are long hex strings. `getUsername()` converts them into memorable usernames for your UI.

- Returns: Human-readable username string
- Deterministic: Same publicKey always → same username
- Format: `adjective-noun-verb-number`

> [!IMPORTANT]  
> **Never ask users to create usernames.** DAKU keeps users anonymous. Display the generated username in your UI, but always identify users by their **publicKey** in your database.

---

### `createAuth(privateKey, pow?)`

**Generate authentication token**

```javascript
const token = await createAuth(privateKey, 2); // pow = difficulty
```

Creates a signed auth token with timestamp, nonce, signature, and proof-of-work. Send this to your server for verification.

- Returns: Base64-encoded auth token
- Default POW: 2 (adjust for spam protection)
- Includes: timestamp, nonce, signature, proof-of-work

---

### `verifyAuth(token, pow?)`

**Verify authentication token**

```javascript
const publicKey = await verifyAuth(token, 2);
if (publicKey) {
  // ✅ Valid! User authenticated
  console.log(`User ${publicKey} logged in`);
} else {
  // ❌ Invalid or expired
}
```

Verifies the signature, proof-of-work, and timestamp (must be < 1 minute old). Returns the user's publicKey on success.

- Returns: `publicKey` string or `null`
- Checks: Signature validity, POW correctness, timestamp freshness
- Token lifetime: 1 minute

---

### `sign(message, privateKey, pow?)`

**Sign any message**

```javascript
const { signature, pow } = await sign("hello world", privateKey, 2);
```

Create a cryptographic signature for any message with proof-of-work. Lower-level function used by `createAuth()`.

- Returns: `{ signature: string, pow: number }`
- Use case: Custom message signing beyond authentication

---

### `verify(message, signatureData, publicKey, pow?)`

**Verify any signature**

```javascript
const isValid = await verify("hello world", { signature, pow }, publicKey, 2);
```

Verify a message signature and proof-of-work. Lower-level function used by `verifyAuth()`.

- Returns: `boolean`
- Checks: Signature + POW validity

---

## Express.js Middleware

```javascript
import express from "express";
import { verifyAuth, getUsername } from "daku";

const app = express();

// Middleware: Verify DAKU auth
const daku =
  (powDifficulty = 2) =>
  async (req, res, next) => {
    const token = req.headers["daku"];
    const publicKey = await verifyAuth(token, powDifficulty);

    if (!publicKey) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    req.userId = publicKey; // Attach user ID
    next();
  };

// Protected route
app.post("/api/profile", daku(), async (req, res) => {
  const username = await getUsername(req.userId);
  res.json({
    message: `Welcome, ${username}!`,
    userId: req.userId,
  });
});

app.listen(3000);
```

---

## Key Benefits

| Traditional Auth                    | DAKU                                   |
| ----------------------------------- | -------------------------------------- |
| Manage passwords, hashes, resets    | No passwords—just verify signatures    |
| Store emails/phones (PII)           | Zero personal data collected           |
| User databases = security liability | Only store public keys (not sensitive) |
| Slow authentication flows           | Instant cryptographic verification     |
| GDPR compliance overhead            | No PII = simpler compliance            |
| Spam = manual moderation/CAPTCHAs   | Built-in proof-of-work protection      |

---

## Features

- **🕵️ Anonymous**: No email, no phone, no personal data
- **🔐 Secure**: secp256k1 signatures (Bitcoin/Ethereum-grade)
- **🛡️ Spam-proof**: Configurable proof-of-work difficulty
- **⚡ Lightweight**: Minimal dependencies, works everywhere
- **🌐 Universal**: Node.js + Browser compatible
- **⏱️ Short-lived tokens**: 1-minute expiration (anti-replay)
- **🌍 Cross-project identity**: Reuse one keypair across apps

---

## Global Identity

Users can reuse **one private key** across multiple services. Same privateKey → same publicKey → same identity everywhere.

```javascript
// User's keypair works on yourapp.com AND anotherapp.com
const publicKey = getPublicKey(samePrivateKey);
// → Same publicKey = consistent cross-platform identity
```

> [!WARNING]  
> Reusing keypairs links user identity across services. This enables seamless cross-app experiences but reduces anonymity between services. For per-app isolation, derive or generate separate keys.

---

## Security Notes

- **Private keys**: Users must store them securely (localStorage, hardware wallets). Lost keys = lost access.
- **Token lifetime**: Hardcoded to 1 minute; prevent replay attacks.
- **POW difficulty**: Default = 2 leading zeros. Increase for high-traffic endpoints (trade-off: slower auth).
- **No server secrets**: DAKU has no shared secrets—everything is public-key cryptography.

---

**DAKU: The authentication system that doesn't know anything about your users. By design.**
