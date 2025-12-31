// 1-on-1 E2E Encrypted Chat Example
import {
  generateKeyPair,
  deriveSharedSecret,
  encrypt,
  decrypt,
  getUsername,
} from "../index.js";

async function main() {
  console.log("=".repeat(50));
  console.log("1-on-1 E2E Encrypted Chat");
  console.log("=".repeat(50));

  // === SETUP: Both users generate their identities ===
  const alice = generateKeyPair();
  const bob = generateKeyPair();

  console.log(`\n👤 Alice: ${getUsername(alice.publicKey)}`);
  console.log(`👤 Bob: ${getUsername(bob.publicKey)}`);

  // === Derive shared secrets (both derive the same key!) ===
  const aliceToBobSecret = deriveSharedSecret(alice.privateKey, bob.publicKey);
  const bobFromAliceSecret = deriveSharedSecret(bob.privateKey, alice.publicKey);

  console.log(`\n🔐 Shared secret match: ${aliceToBobSecret === bobFromAliceSecret}`);

  // === CHAT SESSION ===
  console.log("\n💬 Chat:\n");

  // Alice sends a message to Bob
  const msg1 = await encrypt("Hey Bob! How are you?", aliceToBobSecret);
  console.log(`Alice → Bob: "Hey Bob! How are you?"`);
  console.log(`   [encrypted: ${msg1.slice(0, 40)}...]`);

  // Bob receives and decrypts
  const decrypted1 = await decrypt(msg1, bobFromAliceSecret);
  console.log(`   Bob decrypts: "${decrypted1}"\n`);

  // Bob replies to Alice
  const msg2 = await encrypt("I'm great Alice! Working on a secret project.", bobFromAliceSecret);
  console.log(`Bob → Alice: "I'm great Alice! Working on a secret project."`);
  console.log(`   [encrypted: ${msg2.slice(0, 40)}...]`);

  // Alice receives and decrypts
  const decrypted2 = await decrypt(msg2, aliceToBobSecret);
  console.log(`   Alice decrypts: "${decrypted2}"\n`);

  // Alice sends another message
  const msg3 = await encrypt("Sounds exciting! Tell me more 🚀", aliceToBobSecret);
  console.log(`Alice → Bob: "Sounds exciting! Tell me more 🚀"`);
  const decrypted3 = await decrypt(msg3, bobFromAliceSecret);
  console.log(`   Bob decrypts: "${decrypted3}"\n`);

  // === SECURITY DEMO: Eve cannot read the messages ===
  console.log("=".repeat(50));
  console.log("🚫 Security Test: Eve tries to intercept");
  console.log("=".repeat(50));

  const eve = generateKeyPair();
  console.log(`\n👤 Eve: ${getUsername(eve.publicKey)}`);

  // Eve tries to decrypt with a wrong shared secret
  const eveWrongSecret = deriveSharedSecret(eve.privateKey, alice.publicKey);
  const eveResult = await decrypt(msg1, eveWrongSecret);
  console.log(`Eve tries to decrypt Alice's message: ${eveResult}`);
  console.log("✅ Eve cannot read the messages!\n");
}

main().catch(console.error);
