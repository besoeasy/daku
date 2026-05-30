# DAKU

> **Anonymous authentication & encryption. Zero personal data. One library.**

**DAKU** (Punjabi for "bandits") is a minimal cryptographic toolkit for building passwordless, privacy-first applications. No emails, no passwords, no databases of credentials to breach.

```bash
npm install daku
```

---

## Why DAKU?

| Traditional Auth | DAKU |
|------------------|------|
| Store emails & passwords | Just verify signatures |
| Hash passwords, manage resets | No passwords exist |
| GDPR compliance headaches | No PII collected |
| Database = honeypot for hackers | Nothing sensitive to steal |
| OAuth complexity | 3 functions to authenticate |

```javascript
import { generateKeyPair, createAuth, verifyAuth } from "daku";

// User creates identity (client-side, once)
const { privateKey, publicKey } = generateKeyPair();

// User logs in (client-side)
const token = await createAuth(privateKey);

// Server verifies (server-side)
const userId = await verifyAuth(token);  // Returns publicKey or null
```

**That's it.** No signup forms, no email verification, no password resets.

---

## What DAKU Offers

### 🔑 Identity
```javascript
generateKeyPair(seed?)         // Create new keypair identity, optionally deterministic
getPublicKey(privateKey)       // Derive public key from private
getUsername(publicKey)         // Human-readable name like "oceanrunning4523"
```

### 🎫 Authentication
```javascript
createAuth(privateKey, pow?)   // Create login token (with spam protection)
verifyAuth(token, pow?)        // Verify token, returns publicKey or null
```

### ✍️ Signatures
```javascript
sign(message, privateKey, pow?)      // Sign any data
verify(message, sig, publicKey, pow?)  // Verify signature
sha256(message)                      // SHA-256 hash
```

### 🔐 E2E Encryption
```javascript
deriveSharedSecret(myPrivate, theirPublic)  // ECDH key agreement
encrypt(plaintext, key)                      // AES-256-GCM encrypt
decrypt(ciphertext, key)                     // AES-256-GCM decrypt
```

---

## 20+ Use Cases

| # | Use Case |
|---|----------|
| 1 | **Anonymous chat apps** — Users communicate without revealing identity or phone numbers |
| 2 | **Passwordless API authentication** — Clients sign requests instead of using API keys |
| 3 | **End-to-end encrypted messaging** — Private conversations only sender and receiver can read |
| 4 | **Anonymous feedback systems** — Collect honest feedback without identifying who submitted it |
| 5 | **Whistleblower platforms** — Secure, anonymous submission of sensitive information to journalists |
| 6 | **Decentralized identity** — Users own their identity, no central authority controls access |
| 7 | **IoT device authentication** — Devices authenticate without passwords or certificate authorities |
| 8 | **Wallet-based login** — Same keys work with Bitcoin/Ethereum ecosystems (secp256k1) |
| 9 | **Document signing** — Cryptographically sign contracts, agreements, or any digital document |
| 10 | **Anonymous voting systems** — Verify votes are legitimate without revealing who voted |
| 11 | **Encrypted file sharing** — Share files that only intended recipients can decrypt |
| 12 | **Private note-taking apps** — Notes encrypted locally, unreadable even if server breached |
| 13 | **Spam-resistant forms** — Proof-of-work prevents bots from mass-submitting without CAPTCHAs |
| 14 | **Multiplayer game authentication** — Players authenticate without creating accounts or emails |
| 15 | **Anonymous support tickets** — Users get help without revealing personal information |
| 16 | **Secure configuration sharing** — Share secrets between team members with E2E encryption |
| 17 | **Timestamped proof of existence** — Sign documents to prove they existed at specific time |
| 18 | **Private health apps** — Health data stays encrypted, only user can access it |
| 19 | **Anonymous marketplace** — Buy/sell without linking transactions to real identity |
| 20 | **Encrypted backups** — Backup data that only you can restore, even on untrusted storage |
| 21 | **CLI tool authentication** — Command-line tools authenticate without browser OAuth flows |
| 22 | **Peer-to-peer apps** — Direct encrypted communication between users without servers |
| 23 | **Private analytics** — Collect anonymous usage data without tracking individuals |
| 24 | **Secure team collaboration** — Group encryption for team channels and shared documents |

---

## How It Works

### Authentication Flow
```
┌─────────────────────────────────────────────────────────────┐
│ CLIENT                                                      │
│                                                             │
│  1. First visit: generateKeyPair() → save privateKey        │
│  2. Login: createAuth(privateKey) → token                   │
│  3. Send token to server                                    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ SERVER                                                      │
│                                                             │
│  1. verifyAuth(token) → publicKey (user ID)                 │
│  2. publicKey is the unique, permanent user identifier      │
│  3. No passwords, no emails, no database of credentials     │
└─────────────────────────────────────────────────────────────┘
```

### E2E Encryption Flow
```
Alice                                          Bob
  │                                             │
  │  1. deriveSharedSecret(alice.priv, bob.pub) │
  │     ═══════════════════════════════════     │
  │         (Both derive SAME secret)           │
  │     ═══════════════════════════════════     │
  │  2. deriveSharedSecret(bob.priv, alice.pub) │
  │                                             │
  │  3. encrypt("Hello", secret) ──────────────►│
  │                              ◄──────────────│ 4. decrypt(cipher, secret)
  │                                             │
  └─────────────────────────────────────────────┘
        Only Alice & Bob can read messages
```

### Group Encryption
```javascript
import { deriveSharedSecret, encrypt, decrypt } from "daku";
import crypto from "node:crypto";

// Admin creates group key (just random 32 bytes)
const groupKey = crypto.randomBytes(32).toString("hex");

// Distribute to each member securely
for (const member of members) {
  const secret = deriveSharedSecret(admin.privateKey, member.publicKey);
  const encryptedKey = await encrypt(groupKey, secret);
  // Send encryptedKey to member
}

// Member decrypts their copy
const memberSecret = deriveSharedSecret(member.privateKey, admin.publicKey);
const groupKey = await decrypt(encryptedKey, memberSecret);

// Everyone encrypts/decrypts with the shared group key
const message = await encrypt("Hello group!", groupKey);
```

---

## Security

| Feature | Implementation |
|---------|----------------|
| **Signatures** | secp256k1 ECDSA (same as Bitcoin/Ethereum) |
| **Encryption** | AES-256-GCM with random 96-bit IV |
| **Key Exchange** | ECDH (Elliptic Curve Diffie-Hellman) |
| **Hashing** | SHA-256 |
| **Spam Protection** | Proof-of-work (configurable difficulty) |
| **Token Expiry** | Auth tokens valid for 1 minute only |

### What DAKU Protects Against
- ✅ Password breaches (no passwords exist)
- ✅ Credential stuffing (nothing to stuff)
- ✅ Phishing (no credentials to phish)
- ✅ Database leaks (no PII stored)
- ✅ Replay attacks (1-minute token expiry)
- ✅ Spam/bots (proof-of-work)
- ✅ Man-in-the-middle (E2E encryption)

### User Responsibilities
- 🔑 Users must securely store their private key
- 🔑 Lost private key = lost identity (no recovery)
- 🔑 Compromised private key = compromised identity

---

## Examples

### Express.js Middleware
```javascript
import { verifyAuth, getUsername } from "daku";

async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  
  const publicKey = await verifyAuth(token);
  if (!publicKey) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  
  req.userId = publicKey;
  req.username = getUsername(publicKey);
  next();
}
```

### React Login
```javascript
import { generateKeyPair, createAuth } from "daku";

function useAuth() {
  const login = async () => {
    let privateKey = localStorage.getItem("privateKey");
    
    if (!privateKey) {
      const keys = generateKeyPair();
      privateKey = keys.privateKey;
      localStorage.setItem("privateKey", privateKey);
    }
    
    const token = await createAuth(privateKey);
    return fetch("/api/login", {
      headers: { Authorization: `Bearer ${token}` }
    });
  };
  
  return { login };
}
```

### Encrypted Chat
```javascript
import { deriveSharedSecret, encrypt, decrypt } from "daku";

// Both users derive the same shared secret
const secret = deriveSharedSecret(myPrivateKey, theirPublicKey);

// Send encrypted message
const encrypted = await encrypt("Hello!", secret);
ws.send(encrypted);

// Receive and decrypt
ws.onmessage = async (e) => {
  const message = await decrypt(e.data, secret);
  console.log(message);
};
```

---

## API Reference

### `generateKeyPair(seed?)`
Creates a new secp256k1 keypair. Pass a string or byte seed to derive the same keypair deterministically.
```javascript
const { privateKey, publicKey } = generateKeyPair();
// privateKey: 64-char hex (keep secret!)
// publicKey: 66-char hex (share freely)

const sameKeys = generateKeyPair("alice-seed");
```

### `getPublicKey(privateKey)`
Derives public key from private key.
```javascript
const publicKey = getPublicKey(privateKey);
```

### `getUsername(publicKey)`
Generates a deterministic human-readable username.
```javascript
const name = getUsername(publicKey); // "oceanrunning4523"
```

### `createAuth(privateKey, pow?)`
Creates a signed authentication token. Default POW difficulty is 2.
```javascript
const token = await createAuth(privateKey);
const token = await createAuth(privateKey, 3); // Higher difficulty
```

### `verifyAuth(token, pow?)`
Verifies an auth token. Returns `publicKey` on success, `null` on failure.
```javascript
const publicKey = await verifyAuth(token);
if (publicKey) {
  // Authenticated! publicKey is the user ID
}
```

### `sign(message, privateKey, pow?)`
Signs a message with proof-of-work.
```javascript
const sig = await sign("Hello", privateKey);
// { signature: "...", pow: 123 }
```

### `verify(message, signatureData, publicKey, pow?)`
Verifies a signature.
```javascript
const isValid = await verify("Hello", sig, publicKey);
```

### `sha256(message)`
SHA-256 hash.
```javascript
const hash = await sha256("Hello"); // Uint8Array(32)
```

### `deriveSharedSecret(myPrivateKey, theirPublicKey)`
ECDH key agreement. Both parties derive the same secret.
```javascript
const secret = deriveSharedSecret(alice.privateKey, bob.publicKey);
// Same as: deriveSharedSecret(bob.privateKey, alice.publicKey)
```

### `encrypt(plaintext, key)`
AES-256-GCM encryption.
```javascript
const ciphertext = await encrypt("Secret message", sharedSecret);
```

### `decrypt(ciphertext, key)`
AES-256-GCM decryption. Returns `null` on failure.
```javascript
const plaintext = await decrypt(ciphertext, sharedSecret);
```

---

## Comparison

| Feature | DAKU | Passport.js | Auth0 | Firebase Auth |
|---------|------|-------------|-------|---------------|
| No passwords | ✅ | ❌ | ❌ | ❌ |
| No email required | ✅ | ❌ | ❌ | ❌ |
| No database needed | ✅ | ❌ | ❌ | ❌ |
| E2E encryption | ✅ | ❌ | ❌ | ❌ |
| Self-hosted | ✅ | ✅ | ❌ | ❌ |
| Zero dependencies* | ✅ | ❌ | ❌ | ❌ |
| Works offline | ✅ | ❌ | ❌ | ❌ |
| Bundle size | ~50KB | ~200KB | SDK required | SDK required |

*Only 2 peer dependencies: `@noble/secp256k1` and `@noble/hashes`

---

## Installation

```bash
npm install daku
```

**Requirements:** Node.js 16+ or modern browser

---

## License

ISC © [besoeasy](https://github.com/besoeasy)

---

<p align="center">
  <b>Leave no trace. Just authenticate.</b>
</p>
