// Group E2E Encrypted Chat Example
// Shows how to compose group encryption from DAKU primitives
import {
  generateKeyPair,
  getUsername,
  deriveSharedSecret,
  encrypt,
  decrypt,
} from "../index.js";

async function main() {
  console.log("=".repeat(50));
  console.log("Group E2E Chat (using DAKU primitives)");
  console.log("=".repeat(50));

  // === SETUP: Users create their identities ===
  const admin = generateKeyPair();
  const bob = generateKeyPair();
  const carol = generateKeyPair();

  console.log("\n👥 Group Members:");
  console.log(`   👑 Admin: ${getUsername(admin.publicKey)}`);
  console.log(`   👤 Bob: ${getUsername(bob.publicKey)}`);
  console.log(`   👤 Carol: ${getUsername(carol.publicKey)}`);

  // === CREATE GROUP KEY (just random 32 bytes) ===
  console.log("\n🔑 Creating group...");
  const crypto = await import("node:crypto");
  const groupKey = crypto.randomBytes(32).toString("hex");
  console.log(`   Group key: ${groupKey.slice(0, 16)}...`);

  // === DISTRIBUTE KEY TO MEMBERS ===
  console.log("\n📤 Distributing keys...");

  // Admin encrypts group key for each member
  const secretForBob = deriveSharedSecret(admin.privateKey, bob.publicKey);
  const secretForCarol = deriveSharedSecret(admin.privateKey, carol.publicKey);

  const keyForBob = await encrypt(groupKey, secretForBob);
  const keyForCarol = await encrypt(groupKey, secretForCarol);

  console.log(`   → Bob: ${keyForBob.slice(0, 30)}...`);
  console.log(`   → Carol: ${keyForCarol.slice(0, 30)}...`);

  // === MEMBERS DECRYPT THEIR GROUP KEY ===
  console.log("\n🔓 Members decrypt group keys...");

  const bobSecret = deriveSharedSecret(bob.privateKey, admin.publicKey);
  const carolSecret = deriveSharedSecret(carol.privateKey, admin.publicKey);

  const bobGroupKey = await decrypt(keyForBob, bobSecret);
  const carolGroupKey = await decrypt(keyForCarol, carolSecret);

  console.log(`   Bob got key: ${bobGroupKey === groupKey ? "✅" : "❌"}`);
  console.log(`   Carol got key: ${carolGroupKey === groupKey ? "✅" : "❌"}`);

  // === GROUP CHAT ===
  console.log("\n💬 Group Chat:\n");

  // Admin sends
  const msg1 = await encrypt("Welcome everyone! 🎉", groupKey);
  console.log(`Admin: Welcome everyone! 🎉`);
  console.log(`   Bob reads: "${await decrypt(msg1, bobGroupKey)}"`);

  // Bob sends
  const msg2 = await encrypt("Thanks for the invite!", bobGroupKey);
  console.log(`Bob: ${await decrypt(msg2, groupKey)}`);

  // Carol sends
  const msg3 = await encrypt("Great to be here! 👋", carolGroupKey);
  console.log(`Carol: ${await decrypt(msg3, bobGroupKey)}`);

  // === REMOVE MEMBER (key rotation) ===
  console.log("\n" + "=".repeat(50));
  console.log("🔄 Removing Carol (key rotation)");
  console.log("=".repeat(50));

  // Create new group key
  const newGroupKey = crypto.randomBytes(32).toString("hex");

  // Only send to Bob (not Carol)
  const newSecretForBob = deriveSharedSecret(admin.privateKey, bob.publicKey);
  const newKeyForBob = await encrypt(newGroupKey, newSecretForBob);

  // Bob decrypts new key
  const bobNewKey = await decrypt(newKeyForBob, bobSecret);
  console.log(`\n   Bob got new key: ✅`);
  console.log(`   Carol: ❌ (removed)`);

  // New message Carol can't read
  const secretMsg = await encrypt("Carol can't see this!", newGroupKey);
  console.log(`\n   Admin: Carol can't see this!`);
  console.log(`   Bob reads: "${await decrypt(secretMsg, bobNewKey)}"`);
  console.log(`   Carol tries: ${await decrypt(secretMsg, carolGroupKey)}`);
}

main().catch(console.error);
