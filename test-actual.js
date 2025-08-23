// Test with our actual implementation
const crypto = require('./dist/utils/crypto.js');
const ratchet = require('./dist/utils/ratchet.js');

const alice = crypto.generateKeyPair();
const bob = crypto.generateKeyPair();

console.log('=== Initialize ===');
let aliceState = ratchet.initializeRatchet(alice, bob.publicKey);
let bobState = ratchet.initializeRatchet(bob, alice.publicKey);

console.log('Alice initial:', {
  hasTheirEph: aliceState.theirLatestEphemeralPublicKey !== null,
  sendCounter: aliceState.sendMessageCounter
});

console.log('Bob initial:', {
  hasTheirEph: bobState.theirLatestEphemeralPublicKey !== null,
  sendCounter: bobState.sendMessageCounter
});

// Message 1: Alice → Bob
console.log('\n=== Message 1: Alice → Bob ===');
const msg1 = new TextEncoder().encode('Hello Bob');
const [enc1, aliceState2] = ratchet.ratchetEncrypt(aliceState, msg1);

console.log('Alice after encrypt:', {
  hasTheirEph: aliceState2.theirLatestEphemeralPublicKey !== null,
  sendCounter: aliceState2.sendMessageCounter,
  myEph: Buffer.from(aliceState2.myCurrentEphemeralKeyPair.publicKey).toString('hex').slice(0, 8)
});

// Parse message header to see what Alice sent
const version = enc1[0];
const ephemeral = enc1.slice(1, 33);
const prevCounter = new DataView(enc1.buffer, enc1.byteOffset + 33, 4).getUint32(0, false);
const msgCounter = new DataView(enc1.buffer, enc1.byteOffset + 37, 4).getUint32(0, false);

console.log('Message header:', {
  ephemeral: Buffer.from(ephemeral).toString('hex').slice(0, 8),
  prevCounter,
  msgCounter
});

try {
  const [dec1, bobState2] = ratchet.ratchetDecrypt(bobState, enc1);
  console.log('Bob decrypted:', new TextDecoder().decode(dec1));
  console.log('Bob after decrypt:', {
    hasTheirEph: bobState2.theirLatestEphemeralPublicKey !== null,
    theirEph: bobState2.theirLatestEphemeralPublicKey ? 
      Buffer.from(bobState2.theirLatestEphemeralPublicKey).toString('hex').slice(0, 8) : null
  });
  
  // Message 2: Bob → Alice
  console.log('\n=== Message 2: Bob → Alice ===');
  console.log('Bob before encrypt:', {
    hasTheirEph: bobState2.theirLatestEphemeralPublicKey !== null,
    willRatchet: bobState2.theirLatestEphemeralPublicKey !== null
  });
  
  const msg2 = new TextEncoder().encode('Hello Alice');
  const [enc2, bobState3] = ratchet.ratchetEncrypt(bobState2, msg2);
  
  console.log('Bob after encrypt:', {
    myEph: Buffer.from(bobState3.myCurrentEphemeralKeyPair.publicKey).toString('hex').slice(0, 8),
    sendCounter: bobState3.sendMessageCounter
  });
  
  // Parse Bob's message
  const bobEph = enc2.slice(1, 33);
  const bobPrevCounter = new DataView(enc2.buffer, enc2.byteOffset + 33, 4).getUint32(0, false);
  const bobMsgCounter = new DataView(enc2.buffer, enc2.byteOffset + 37, 4).getUint32(0, false);
  
  console.log('Bob message header:', {
    ephemeral: Buffer.from(bobEph).toString('hex').slice(0, 8),
    prevCounter: bobPrevCounter,
    msgCounter: bobMsgCounter
  });
  
  console.log('\nAlice before decrypt:', {
    hasTheirEph: aliceState2.theirLatestEphemeralPublicKey !== null,
    myEph: Buffer.from(aliceState2.myCurrentEphemeralKeyPair.publicKey).toString('hex').slice(0, 8)
  });
  
  try {
    const [dec2, aliceState3] = ratchet.ratchetDecrypt(aliceState2, enc2);
    console.log('Alice decrypted:', new TextDecoder().decode(dec2));
    console.log('SUCCESS!');
  } catch (e) {
    console.log('Alice decrypt FAILED:', e.message);
  }
} catch (e) {
  console.log('Bob decrypt FAILED:', e.message);
}