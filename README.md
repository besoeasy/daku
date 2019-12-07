# daku

> Leave no trace. Just authenticate.

Cryptographic authentication library with built-in proof-of-work spam protection. No emails, no passwords, no personal data.

## Installation

```bash
npm install daku
```

## Quick Start

### 1. Generate a Keypair

```javascript
import { generateKeyPair } from 'daku';

// Generate once and store securely (localStorage, secure storage, etc.)
const { privateKey, publicKey } = generateKeyPair();
```

### 2. Client-Side: Create Authentication Request

```javascript
import { createAuth } from 'daku';

// Create authentication token (includes timestamp, nonce, signature, and POW)
const token = await createAuth(privateKey);

// Send to your server
fetch('/api/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'daku': token
  }
});
```

### 3. Server-Side: Verify Authentication

```javascript
import { verifyAuth } from 'daku';

const publicKey = await verifyAuth(req.headers['daku']);

if (publicKey) {
  // ✅ Authenticated! Use publicKey as unique user ID
  console.log(`User ${publicKey} authenticated`);
} else {
  // ❌ Invalid or expired authentication
  res.status(401).json({ error: 'Unauthorized' });
}
```

## ExpressJS Middleware

```javascript
import express from 'express';
import { verifyAuth } from 'daku';

const app = express();

// Reusable authentication middleware
const daku = (powDifficulty = 2) => {
  return async (req, res, next) => {
    const token = req.headers['daku'];
    
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const publicKey = await verifyAuth(token, powDifficulty);

    if (!publicKey) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    // Attach user's public key to request
    req.userId = publicKey;
    next();
  };
};

// Use on protected routes
app.post('/api/protected', daku(), (req, res) => {
  res.json({ 
    message: 'Access granted',
    userId: req.userId 
  });
});

// Use with custom POW difficulty
app.post('/api/high-security', daku(4), (req, res) => {
  res.json({ message: 'High security endpoint' });
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

### Authentication Functions

#### `createAuth(privateKey, pow = 2)`

Creates a complete authentication token with timestamp, nonce, signature, and proof-of-work.

**Returns:** String (base64-encoded token)

**Example:**
```javascript
const token = await createAuth(privateKey);
// "eyJwdWJsaWNrZXkiOiIwMmE..."
```

#### `verifyAuth(token, pow = 2)`

Verifies authentication token. Checks signature validity, proof-of-work, and timestamp (must be within 1 minute).

**Returns:** `publicKey` string on success, `null` on failure

**Example:**
```javascript
const publicKey = await verifyAuth(token);
```

---

### General Signing Functions

Use these for signing arbitrary messages (not authentication).

#### `sign(message, privateKey, pow = 2)`

Signs any message with proof-of-work.

**Returns:** Object with `{ signature, pow }`

**Example:**
```javascript
const result = await sign('Hello World', privateKey);
// { signature: 'a1b2c3...', pow: 42 }
```

#### `verify(message, signatureData, publicKey, pow = 2)`

Verifies a signed message.

**Returns:** `true` if valid, `false` otherwise

**Example:**
```javascript
const isValid = await verify('Hello World', { signature: 'a1b2...', pow: 42 }, publicKey);
```

---

### Utility Functions

#### `generateKeyPair()`

Generates a new secp256k1 keypair.

**Returns:** `{ privateKey: string, publicKey: string }`

#### `getPublicKey(privateKey)`

Derives the public key from a private key.

**Returns:** `string` (compressed public key in hex)

#### `sha256(message)`

SHA-256 hash helper.

**Returns:** `Uint8Array`

## Use Cases

- **Authentication**: Use `createAuth()` + `verifyAuth()` for login flows
- **Message Signing**: Use `sign()` + `verify()` for arbitrary data signatures
- **Spam Prevention**: POW difficulty prevents automated abuse
- **Privacy-First Apps**: No PII required, just cryptographic proofs

## License

ISC
