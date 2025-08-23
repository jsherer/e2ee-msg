// Test Signal protocol logic
const nacl = require('tweetnacl');

function dh(privateKey, publicKey) {
  return nacl.box.before(publicKey, privateKey);
}

function kdfRootKey(rootKey, dhOutput) {
  const input = new Uint8Array(rootKey.length + dhOutput.length);
  input.set(rootKey, 0);
  input.set(dhOutput, rootKey.length);
  const output = nacl.hash(input);
  return [output.slice(0, 32), output.slice(32, 64)];
}

function kdfChainKey(chainKey) {
  const messageKeyInput = new Uint8Array(chainKey.length + 1);
  messageKeyInput.set(chainKey, 0);
  messageKeyInput[chainKey.length] = 0x01;
  
  const chainKeyInput = new Uint8Array(chainKey.length + 1);
  chainKeyInput.set(chainKey, 0);
  chainKeyInput[chainKey.length] = 0x02;
  
  const messageKey = nacl.hash(messageKeyInput).slice(0, 32);
  const nextChainKey = nacl.hash(chainKeyInput).slice(0, 32);
  
  return [messageKey, nextChainKey];
}

console.log('=== Signal Double Ratchet Protocol ===\n');

// Setup
const alice = nacl.box.keyPair();
const bob = nacl.box.keyPair();

const sharedSecret = dh(alice.secretKey, bob.publicKey);
const hashedSecret = nacl.hash(sharedSecret);

let aliceState = {
  rootKey: hashedSecret.slice(0, 32),
  sendChain: hashedSecret.slice(32, 64),
  recvChain: new Uint8Array(hashedSecret.slice(32, 64)),
  myEph: nacl.box.keyPair(),
  theirEph: null,
  sendCounter: 0
};

let bobState = {
  rootKey: new Uint8Array(hashedSecret.slice(0, 32)),
  sendChain: new Uint8Array(hashedSecret.slice(32, 64)),
  recvChain: new Uint8Array(hashedSecret.slice(32, 64)),
  myEph: nacl.box.keyPair(),
  theirEph: null,
  sendCounter: 0
};

console.log('Initial setup complete\n');

// Message 1: Alice → Bob
console.log('=== Message 1: Alice → Bob ===');
console.log('Alice sends with ephemeral A1, counter=0');
console.log('No ratchet (Bob\'s ephemeral unknown)');
const [aliceMsg1Key] = kdfChainKey(aliceState.sendChain);
console.log('Message key:', Buffer.from(aliceMsg1Key).toString('hex').slice(0, 8));

// Bob receives
console.log('\nBob receives:');
console.log('Sees ephemeral A1 for first time');
console.log('Stores A1, no ratchet yet');
bobState.theirEph = aliceState.myEph.publicKey;
const [bobMsg1Key] = kdfChainKey(bobState.recvChain);
console.log('Message key:', Buffer.from(bobMsg1Key).toString('hex').slice(0, 8));
console.log('Match?', Buffer.from(aliceMsg1Key).equals(Buffer.from(bobMsg1Key)));

// Message 2: Bob → Alice  
console.log('\n=== Message 2: Bob → Alice ===');
console.log('Bob has Alice\'s ephemeral A1, so he ratchets:');

// Bob's ratchet
const bobNewEph = nacl.box.keyPair();
const bobDH = dh(bobNewEph.secretKey, bobState.theirEph);
const [bobNewRoot, bobNewSend] = kdfRootKey(bobState.rootKey, bobDH);

console.log('1. Generate new ephemeral B1');
console.log('2. DH(B1_priv, A1_pub)');
console.log('3. New root = KDF_RK(old_root, dh_output)');
console.log('4. New send chain from new root');

bobState.myEph = bobNewEph;
bobState.rootKey = bobNewRoot;
bobState.sendChain = bobNewSend;
bobState.sendCounter = 0; // Reset for new chain

console.log('Bob sends with ephemeral B1, counter=0');
const [bobMsg2Key] = kdfChainKey(bobState.sendChain);
console.log('Message key:', Buffer.from(bobMsg2Key).toString('hex').slice(0, 8));

// Alice receives
console.log('\nAlice receives:');
console.log('Sees ephemeral B1 for first time');
console.log('Message has new ephemeral AND counter=0');
console.log('This means Bob ratcheted, so Alice must too:');

// Alice must perform matching ratchet to decrypt
aliceState.theirEph = bobState.myEph.publicKey;
const aliceDH = dh(aliceState.myEph.secretKey, aliceState.theirEph);
const [aliceNewRoot, aliceNewRecv] = kdfRootKey(aliceState.rootKey, aliceDH);

console.log('1. DH(A1_priv, B1_pub)');
console.log('2. New root = KDF_RK(old_root, dh_output)');
console.log('3. New recv chain from new root');

aliceState.rootKey = aliceNewRoot;
aliceState.recvChain = aliceNewRecv;

const [aliceMsg2Key] = kdfChainKey(aliceState.recvChain);
console.log('Message key:', Buffer.from(aliceMsg2Key).toString('hex').slice(0, 8));
console.log('Match?', Buffer.from(bobMsg2Key).equals(Buffer.from(aliceMsg2Key)));

// Verify DH commutativity
console.log('\n=== DH Verification ===');
console.log('Bob: DH(B1_priv, A1_pub) =', Buffer.from(bobDH).toString('hex').slice(0, 8));
console.log('Alice: DH(A1_priv, B1_pub) =', Buffer.from(aliceDH).toString('hex').slice(0, 8));
console.log('Equal?', Buffer.from(bobDH).equals(Buffer.from(aliceDH)));