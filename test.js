// DAKU Test Suite
import {
  generateKeyPair,
  getPublicKey,
  getUsername,
  sha256,
  sign,
  verify,
  createAuth,
  verifyAuth,
  deriveSharedSecret,
  encrypt,
  decrypt,
} from "./index.js";

let passed = 0;
let failed = 0;

function assert(condition, testName) {
  if (condition) {
    console.log(`✅ ${testName}`);
    passed++;
  } else {
    console.log(`❌ ${testName}`);
    failed++;
  }
}

async function runTests() {
  console.log("=".repeat(60));
  console.log("DAKU Test Suite");
  console.log("=".repeat(60));

  // ==========================================================================
  // KEY GENERATION
  // ==========================================================================
  console.log("\n📦 Key Generation\n");

  const alice = generateKeyPair();
  assert(alice.privateKey && alice.privateKey.length === 64, "generateKeyPair() returns privateKey (32 bytes hex)");
  assert(alice.publicKey && alice.publicKey.length === 66, "generateKeyPair() returns publicKey (33 bytes compressed hex)");

  const bob = generateKeyPair();
  assert(alice.privateKey !== bob.privateKey, "generateKeyPair() generates unique keys");

  // ==========================================================================
  // GET PUBLIC KEY
  // ==========================================================================
  console.log("\n🔑 Get Public Key\n");

  const derivedPublicKey = getPublicKey(alice.privateKey);
  assert(derivedPublicKey === alice.publicKey, "getPublicKey() derives correct public key from private key");

  // ==========================================================================
  // USERNAME GENERATION
  // ==========================================================================
  console.log("\n👤 Username Generation\n");

  const username = getUsername(alice.publicKey);
  assert(typeof username === "string" && username.length > 0, "getUsername() returns a string");

  const username2 = getUsername(alice.publicKey);
  assert(username === username2, "getUsername() is deterministic (same input = same output)");

  const bobUsername = getUsername(bob.publicKey);
  assert(username !== bobUsername, "getUsername() generates different usernames for different keys");

  // ==========================================================================
  // SHA-256 HASHING
  // ==========================================================================
  console.log("\n#️⃣ SHA-256 Hashing\n");

  const hash1 = await sha256("hello");
  const hash2 = await sha256("hello");
  assert(hash1.length === 32, "sha256() returns 32 bytes");
  assert(JSON.stringify(Array.from(hash1)) === JSON.stringify(Array.from(hash2)), "sha256() is deterministic");

  const hash3 = await sha256("world");
  assert(JSON.stringify(Array.from(hash1)) !== JSON.stringify(Array.from(hash3)), "sha256() different input = different hash");

  // ==========================================================================
  // SIGN & VERIFY
  // ==========================================================================
  console.log("\n✍️ Sign & Verify\n");

  const message = "Hello, this is a test message!";
  const signatureData = await sign(message, alice.privateKey, 1);
  assert(signatureData.signature && signatureData.signature.length === 128, "sign() returns signature (64 bytes hex)");
  assert(typeof signatureData.pow === "number", "sign() returns proof-of-work nonce");

  const isValid = await verify(message, signatureData, alice.publicKey, 1);
  assert(isValid === true, "verify() returns true for valid signature");

  const isInvalid = await verify("tampered message", signatureData, alice.publicKey, 1);
  assert(isInvalid === false, "verify() returns false for tampered message");

  const wrongKey = await verify(message, signatureData, bob.publicKey, 1);
  assert(wrongKey === false, "verify() returns false for wrong public key");

  // ==========================================================================
  // AUTH TOKEN
  // ==========================================================================
  console.log("\n🎫 Auth Token\n");

  const authToken = await createAuth(alice.privateKey, 1);
  assert(typeof authToken === "string" && authToken.length > 0, "createAuth() returns base64 token");

  const verifiedPublicKey = await verifyAuth(authToken, 1);
  assert(verifiedPublicKey === alice.publicKey, "verifyAuth() returns correct public key");

  const invalidToken = await verifyAuth("invalid-token", 1);
  assert(invalidToken === null, "verifyAuth() returns null for invalid token");

  // Test expired token (manipulate timestamp)
  const expiredPayload = JSON.parse(Buffer.from(authToken, "base64").toString());
  expiredPayload.timestamp = Date.now() - 120000; // 2 minutes ago
  expiredPayload.message = `${expiredPayload.timestamp}:${expiredPayload.nonce}`;
  const expiredToken = Buffer.from(JSON.stringify(expiredPayload)).toString("base64");
  const expiredResult = await verifyAuth(expiredToken, 1);
  assert(expiredResult === null, "verifyAuth() returns null for expired token (>1 min)");

  // ==========================================================================
  // E2E ENCRYPTION - ECDH
  // ==========================================================================
  console.log("\n🔐 E2E Encryption (ECDH)\n");

  const aliceSecret = deriveSharedSecret(alice.privateKey, bob.publicKey);
  const bobSecret = deriveSharedSecret(bob.privateKey, alice.publicKey);
  assert(aliceSecret === bobSecret, "deriveSharedSecret() both parties derive same secret");
  assert(aliceSecret.length === 64, "deriveSharedSecret() returns 32-byte hex key");

  // ==========================================================================
  // ENCRYPT & DECRYPT
  // ==========================================================================
  console.log("\n🔒 Encrypt & Decrypt\n");

  const plaintext = "Secret message for Bob!";
  const ciphertext = await encrypt(plaintext, aliceSecret);
  assert(typeof ciphertext === "string" && ciphertext.length > 0, "encrypt() returns hex ciphertext");
  assert(ciphertext !== plaintext, "encrypt() ciphertext differs from plaintext");

  const decrypted = await decrypt(ciphertext, bobSecret);
  assert(decrypted === plaintext, "decrypt() recovers original plaintext");

  const wrongKeyDecrypt = await decrypt(ciphertext, "0".repeat(64));
  assert(wrongKeyDecrypt === null, "decrypt() returns null with wrong key");

  // Test different messages produce different ciphertexts
  const ciphertext2 = await encrypt(plaintext, aliceSecret);
  assert(ciphertext !== ciphertext2, "encrypt() produces different ciphertext each time (random IV)");

  // ==========================================================================
  // GROUP ENCRYPTION (using primitives)
  // ==========================================================================
  console.log("\n👥 Group Encryption (composed from primitives)\n");

  const admin = generateKeyPair();
  const member1 = generateKeyPair();
  const member2 = generateKeyPair();

  // Create group key (just random 32 bytes)
  const crypto = await import("node:crypto");
  const groupKey = crypto.randomBytes(32).toString("hex");
  assert(groupKey.length === 64, "Group key is 32-byte hex");

  // Distribute key to members using deriveSharedSecret + encrypt
  const secret1 = deriveSharedSecret(admin.privateKey, member1.publicKey);
  const secret2 = deriveSharedSecret(admin.privateKey, member2.publicKey);
  const encryptedKeyForMember1 = await encrypt(groupKey, secret1);
  const encryptedKeyForMember2 = await encrypt(groupKey, secret2);

  // Members decrypt their group key
  const member1Secret = deriveSharedSecret(member1.privateKey, admin.publicKey);
  const member2Secret = deriveSharedSecret(member2.privateKey, admin.publicKey);
  const member1GroupKey = await decrypt(encryptedKeyForMember1, member1Secret);
  const member2GroupKey = await decrypt(encryptedKeyForMember2, member2Secret);

  assert(member1GroupKey === groupKey, "Member 1 decrypts correct group key");
  assert(member2GroupKey === groupKey, "Member 2 decrypts correct group key");

  // Group messaging (encrypt with group key directly)
  const groupMessage = "Hello group!";
  const encryptedGroupMsg = await encrypt(groupMessage, groupKey);
  const decrypted1 = await decrypt(encryptedGroupMsg, member1GroupKey);
  const decrypted2 = await decrypt(encryptedGroupMsg, member2GroupKey);

  assert(decrypted1 === groupMessage, "Member 1 decrypts group message");
  assert(decrypted2 === groupMessage, "Member 2 decrypts group message");

  // ==========================================================================
  // SUMMARY
  // ==========================================================================
  console.log("\n" + "=".repeat(60));
  console.log(`RESULTS: ${passed} passed, ${failed} failed`);
  console.log("=".repeat(60));

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error("Test suite error:", err);
  process.exit(1);
});
