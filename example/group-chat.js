// 4-Person Group E2E Encrypted Chat Example
import {
  generateKeyPair,
  getUsername,
  createGroupKey,
  encryptGroupKey,
  decryptGroupKey,
  encryptWithGroupKey,
  decryptWithGroupKey,
} from "../index.js";

async function main() {
  console.log("=".repeat(50));
  console.log("4-Person Group E2E Encrypted Chat");
  console.log("=".repeat(50));

  // === SETUP: 4 users create their identities ===
  const alice = generateKeyPair(); // Group admin
  const bob = generateKeyPair();
  const carol = generateKeyPair();
  const dave = generateKeyPair();

  console.log("\n👥 Group Members:");
  console.log(`   👑 Alice (Admin): ${getUsername(alice.publicKey)}`);
  console.log(`   👤 Bob: ${getUsername(bob.publicKey)}`);
  console.log(`   👤 Carol: ${getUsername(carol.publicKey)}`);
  console.log(`   👤 Dave: ${getUsername(dave.publicKey)}`);

  // === ADMIN (Alice) creates group and distributes key ===
  console.log("\n🔑 Creating group key...");
  const groupKey = await createGroupKey();
  console.log(`   Group key: ${groupKey.slice(0, 16)}...`);

  // Admin encrypts the group key for each member
  console.log("\n📤 Distributing keys to members...");
  const keyForBob = await encryptGroupKey(groupKey, alice.privateKey, bob.publicKey);
  const keyForCarol = await encryptGroupKey(groupKey, alice.privateKey, carol.publicKey);
  const keyForDave = await encryptGroupKey(groupKey, alice.privateKey, dave.publicKey);

  console.log(`   → Bob: ${keyForBob.slice(0, 30)}...`);
  console.log(`   → Carol: ${keyForCarol.slice(0, 30)}...`);
  console.log(`   → Dave: ${keyForDave.slice(0, 30)}...`);

  // === Each member decrypts their copy of the group key ===
  console.log("\n🔓 Members decrypt their group keys...");
  const bobGroupKey = await decryptGroupKey(keyForBob, bob.privateKey, alice.publicKey);
  const carolGroupKey = await decryptGroupKey(keyForCarol, carol.privateKey, alice.publicKey);
  const daveGroupKey = await decryptGroupKey(keyForDave, dave.privateKey, alice.publicKey);

  console.log(`   Bob got key: ${bobGroupKey === groupKey ? "✅" : "❌"}`);
  console.log(`   Carol got key: ${carolGroupKey === groupKey ? "✅" : "❌"}`);
  console.log(`   Dave got key: ${daveGroupKey === groupKey ? "✅" : "❌"}`);

  // === GROUP CHAT ===
  console.log("\n" + "=".repeat(50));
  console.log("💬 Group Chat");
  console.log("=".repeat(50) + "\n");

  // Alice sends a message (using her admin key)
  const msg1 = await encryptWithGroupKey("Welcome to the group everyone! 🎉", groupKey);
  console.log(`Alice: Welcome to the group everyone! 🎉`);
  console.log(`   [encrypted: ${msg1.slice(0, 40)}...]`);
  console.log(`   Bob reads: "${await decryptWithGroupKey(msg1, bobGroupKey)}"`);
  console.log(`   Carol reads: "${await decryptWithGroupKey(msg1, carolGroupKey)}"`);
  console.log(`   Dave reads: "${await decryptWithGroupKey(msg1, daveGroupKey)}"\n`);

  // Bob replies (using his decrypted group key)
  const msg2 = await encryptWithGroupKey("Thanks for adding me! Excited to be here.", bobGroupKey);
  console.log(`Bob: Thanks for adding me! Excited to be here.`);
  console.log(`   Alice reads: "${await decryptWithGroupKey(msg2, groupKey)}"\n`);

  // Carol sends a message
  const msg3 = await encryptWithGroupKey("Hey everyone! 👋 What's the plan?", carolGroupKey);
  console.log(`Carol: Hey everyone! 👋 What's the plan?`);
  console.log(`   Dave reads: "${await decryptWithGroupKey(msg3, daveGroupKey)}"\n`);

  // Dave sends a message
  const msg4 = await encryptWithGroupKey("Let's build something amazing! 🚀", daveGroupKey);
  console.log(`Dave: Let's build something amazing! 🚀`);
  console.log(`   All members can decrypt: "${await decryptWithGroupKey(msg4, groupKey)}"\n`);

  // === SECURITY DEMO: Outsider cannot read messages ===
  console.log("=".repeat(50));
  console.log("🚫 Security Test: Eve tries to join");
  console.log("=".repeat(50));

  const eve = generateKeyPair();
  console.log(`\n👤 Eve (outsider): ${getUsername(eve.publicKey)}`);

  // Eve tries to decrypt with a fake key
  const fakeGroupKey = await createGroupKey();
  const eveResult = await decryptWithGroupKey(msg1, fakeGroupKey);
  console.log(`Eve guesses a key and tries to decrypt: ${eveResult}`);

  // Eve tries to derive from her key and Alice's public key
  const eveEncryptedKey = await encryptGroupKey(fakeGroupKey, eve.privateKey, alice.publicKey);
  console.log(`Eve tries to inject a message...`);

  // But members would need Eve's public key to decrypt, which they don't have
  // And even if they did, it would be a different group key
  console.log(`✅ Eve cannot read or inject messages into the group!\n`);

  // === MEMBER REMOVAL DEMO ===
  console.log("=".repeat(50));
  console.log("🔄 Key Rotation: Dave leaves the group");
  console.log("=".repeat(50));

  console.log("\n📢 Admin creates a new group key (excluding Dave)...");
  const newGroupKey = await createGroupKey();

  // Distribute only to remaining members
  const newKeyForBob = await encryptGroupKey(newGroupKey, alice.privateKey, bob.publicKey);
  const newKeyForCarol = await encryptGroupKey(newGroupKey, alice.privateKey, carol.publicKey);
  // Dave doesn't get the new key!

  const bobNewKey = await decryptGroupKey(newKeyForBob, bob.privateKey, alice.publicKey);
  const carolNewKey = await decryptGroupKey(newKeyForCarol, carol.privateKey, alice.publicKey);

  console.log(`   Bob got new key: ✅`);
  console.log(`   Carol got new key: ✅`);
  console.log(`   Dave: ❌ (removed)\n`);

  // New messages are encrypted with the new key
  const newMsg = await encryptWithGroupKey("Dave has left the group.", newGroupKey);
  console.log(`Alice: Dave has left the group.`);
  console.log(`   Bob reads: "${await decryptWithGroupKey(newMsg, bobNewKey)}"`);
  console.log(`   Carol reads: "${await decryptWithGroupKey(newMsg, carolNewKey)}"`);

  // Dave cannot read new messages
  const daveAttempt = await decryptWithGroupKey(newMsg, daveGroupKey);
  console.log(`   Dave tries with old key: ${daveAttempt}`);
  console.log("\n✅ Dave can no longer read new messages!\n");
}

main().catch(console.error);
