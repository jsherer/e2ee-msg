// Test our actual implementation
const { initializeRatchet, ratchetEncrypt, ratchetDecrypt } = require('./src/utils/ratchet');
const { generateKeyPair } = require('./src/utils/crypto');

const alice = generateKeyPair();
const bob = generateKeyPair();

console.log('=== Initialize ===');
let aliceState = initializeRatchet(alice, bob.publicKey);
let bobState = initializeRatchet(bob, alice.publicKey);

console.log('Alice initial state:');
console.log('  - has their ephemeral?', aliceState.theirLatestEphemeralPublicKey !== null);
console.log('  - send counter:', aliceState.sendMessageCounter);
console.log('  - receive counter:', aliceState.receiveMessageCounter);

console.log('Bob initial state:');
console.log('  - has their ephemeral?', bobState.theirLatestEphemeralPublicKey !== null);
console.log('  - send counter:', bobState.sendMessageCounter);
console.log('  - receive counter:', bobState.receiveMessageCounter);

console.log('\n=== Alice -> Bob (Message 1) ===');
const msg1 = new TextEncoder().encode('Message 1 from Alice');
const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
console.log('Alice after encrypt:');
console.log('  - send counter:', aliceState2.sendMessageCounter);

console.log('Bob before decrypt:');
console.log('  - has their ephemeral?', bobState.theirLatestEphemeralPublicKey !== null);

try {
  const [dec1, bobState2] = ratchetDecrypt(bobState, enc1);
  console.log('Bob after decrypt:');
  console.log('  - message:', new TextDecoder().decode(dec1));
  console.log('  - has their ephemeral?', bobState2.theirLatestEphemeralPublicKey !== null);
  console.log('  - receive counter:', bobState2.receiveMessageCounter);
  
  console.log('\n=== Bob -> Alice (Message 2) ===');
  const msg2 = new TextEncoder().encode('Message 2 from Bob');
  console.log('Bob before encrypt:');
  console.log('  - has their ephemeral?', bobState2.theirLatestEphemeralPublicKey !== null);
  console.log('  - will perform DH ratchet?', bobState2.theirLatestEphemeralPublicKey !== null);
  
  const [enc2, bobState3] = ratchetEncrypt(bobState2, msg2);
  console.log('Bob after encrypt:');
  console.log('  - send counter:', bobState3.sendMessageCounter);
  
  console.log('Alice before decrypt:');
  console.log('  - has their ephemeral?', aliceState2.theirLatestEphemeralPublicKey !== null);
  
  try {
    const [dec2, aliceState3] = ratchetDecrypt(aliceState2, enc2);
    console.log('Alice after decrypt:');
    console.log('  - message:', new TextDecoder().decode(dec2));
    console.log('SUCCESS!');
  } catch (e) {
    console.log('Alice decrypt failed:', e.message);
  }
} catch (e) {
  console.log('Bob decrypt failed:', e.message);
}