// Authentication Example - createAuth & verifyAuth
import {
  generateKeyPair,
  getPublicKey,
  getUsername,
  createAuth,
  verifyAuth,
} from "../index.js";

async function main() {
  console.log("=".repeat(60));
  console.log("DAKU Authentication Example");
  console.log("=".repeat(60));

  // ==========================================================================
  // STEP 1: USER CREATES IDENTITY (once, stored securely)
  // ==========================================================================
  console.log("\n📦 STEP 1: User creates identity\n");

  const user = generateKeyPair();
  console.log(`   Private Key: ${user.privateKey.slice(0, 20)}... (KEEP SECRET!)`);
  console.log(`   Public Key:  ${user.publicKey}`);
  console.log(`   Username:    ${getUsername(user.publicKey)}`);

  // ==========================================================================
  // STEP 2: USER LOGS IN (creates auth token)
  // ==========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("🔐 STEP 2: User creates auth token (client-side)");
  console.log("=".repeat(60));

  console.log("\n   Creating auth token with POW difficulty 2...");
  const startTime = Date.now();
  const authToken = await createAuth(user.privateKey, 2);
  const elapsed = Date.now() - startTime;

  console.log(`   ⏱️  Token created in ${elapsed}ms`);
  console.log(`   📝 Token: ${authToken.slice(0, 50)}...`);
  console.log(`   📏 Token length: ${authToken.length} chars`);

  // Decode and show what's inside (for demo purposes)
  const decoded = JSON.parse(Buffer.from(authToken, "base64").toString());
  console.log("\n   Token contents:");
  console.log(`   ├── publickey: ${decoded.publickey.slice(0, 20)}...`);
  console.log(`   ├── signature: ${decoded.signature.slice(0, 20)}...`);
  console.log(`   ├── pow: ${decoded.pow}`);
  console.log(`   ├── timestamp: ${decoded.timestamp} (${new Date(decoded.timestamp).toISOString()})`);
  console.log(`   └── nonce: ${decoded.nonce.slice(0, 16)}...`);

  // ==========================================================================
  // STEP 3: SERVER VERIFIES TOKEN
  // ==========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("✅ STEP 3: Server verifies auth token");
  console.log("=".repeat(60));

  const verifiedPublicKey = await verifyAuth(authToken, 2);

  if (verifiedPublicKey) {
    console.log("\n   ✅ Authentication successful!");
    console.log(`   👤 User identified: ${getUsername(verifiedPublicKey)}`);
    console.log(`   🔑 Public key: ${verifiedPublicKey}`);
  } else {
    console.log("\n   ❌ Authentication failed!");
  }

  // ==========================================================================
  // STEP 4: DEMONSTRATE INVALID SCENARIOS
  // ==========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("🚫 STEP 4: Invalid token scenarios");
  console.log("=".repeat(60));

  // Invalid token
  console.log("\n   Test 1: Random invalid token");
  const invalidResult = await verifyAuth("invalid-token-here", 2);
  console.log(`   Result: ${invalidResult === null ? "❌ Rejected (correct!)" : "⚠️ Accepted (wrong!)"}`);

  // Tampered token
  console.log("\n   Test 2: Tampered token (modified signature)");
  const tamperedToken = authToken.slice(0, -10) + "aaaaaaaaaa";
  const tamperedResult = await verifyAuth(tamperedToken, 2);
  console.log(`   Result: ${tamperedResult === null ? "❌ Rejected (correct!)" : "⚠️ Accepted (wrong!)"}`);

  // Expired token (simulated)
  console.log("\n   Test 3: Expired token (>1 minute old)");
  const expiredPayload = { ...decoded };
  expiredPayload.timestamp = Date.now() - 120000; // 2 minutes ago
  expiredPayload.message = `${expiredPayload.timestamp}:${expiredPayload.nonce}`;
  const expiredToken = Buffer.from(JSON.stringify(expiredPayload)).toString("base64");
  const expiredResult = await verifyAuth(expiredToken, 2);
  console.log(`   Result: ${expiredResult === null ? "❌ Rejected (correct!)" : "⚠️ Accepted (wrong!)"}`);

  // Wrong POW difficulty
  console.log("\n   Test 4: Token with lower POW than required");
  const lowPowToken = await createAuth(user.privateKey, 1); // Created with POW 1
  const highPowResult = await verifyAuth(lowPowToken, 3);   // Verified with POW 3
  console.log(`   Result: ${highPowResult === null ? "❌ Rejected (correct!)" : "⚠️ Accepted (wrong!)"}`);

  // ==========================================================================
  // STEP 5: REAL-WORLD USAGE PATTERN
  // ==========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("🌐 STEP 5: Real-world usage pattern");
  console.log("=".repeat(60));

  console.log(`
   CLIENT SIDE:
   ─────────────────────────────────────────────────────
   // User's private key stored securely (e.g., localStorage, keychain)
   const privateKey = "stored_private_key";
   
   // Create fresh auth token for each request
   const token = await createAuth(privateKey);
   
   // Send to server
   fetch('/api/protected', {
     headers: { 'Authorization': \`Bearer \${token}\` }
   });

   SERVER SIDE:
   ─────────────────────────────────────────────────────
   // Express middleware example
   async function authMiddleware(req, res, next) {
     const token = req.headers.authorization?.replace('Bearer ', '');
     
     const publicKey = await verifyAuth(token);
     
     if (!publicKey) {
       return res.status(401).json({ error: 'Unauthorized' });
     }
     
     // User is authenticated! publicKey is their unique ID
     req.userId = publicKey;
     req.username = getUsername(publicKey);
     next();
   }
  `);

  // ==========================================================================
  // STEP 6: POW DIFFICULTY COMPARISON
  // ==========================================================================
  console.log("=".repeat(60));
  console.log("⚡ STEP 6: POW difficulty comparison");
  console.log("=".repeat(60));

  for (const difficulty of [1, 2, 3, 4]) {
    const start = Date.now();
    await createAuth(user.privateKey, difficulty);
    const time = Date.now() - start;
    console.log(`   POW ${difficulty}: ${time}ms`);
  }

  console.log(`
   💡 Higher POW = more spam protection, but slower login
   Recommended: POW 2 for normal apps, POW 3-4 for high-security
  `);
}

main().catch(console.error);
