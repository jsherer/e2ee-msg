// Debug the ratchet implementation
const nacl = require('tweetnacl');

// Copy the key functions
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

// Simulate the protocol
const alice = nacl.box.keyPair();
const bob = nacl.box.keyPair();

console.log('=== Setup ===');
// Both compute same initial shared secret
const aliceShared = dh(alice.secretKey, bob.publicKey);
const bobShared = dh(bob.secretKey, alice.publicKey);
console.log('Initial shared equal?', Buffer.from(aliceShared).equals(Buffer.from(bobShared)));

// Initialize states
const aliceHash = nacl.hash(aliceShared);
const bobHash = nacl.hash(bobShared);

let aliceState = {
  rootKey: aliceHash.slice(0, 32),
  sendingChainKey: aliceHash.slice(32, 64),
  receivingChainKey: new Uint8Array(aliceHash.slice(32, 64)),
  myEphemeral: nacl.box.keyPair(),
  theirEphemeral: null
};

let bobState = {
  rootKey: bobHash.slice(0, 32),
  sendingChainKey: bobHash.slice(32, 64),
  receivingChainKey: new Uint8Array(bobHash.slice(32, 64)),
  myEphemeral: nacl.box.keyPair(),
  theirEphemeral: null
};

console.log('\n=== Message 1: Alice → Bob ===');
console.log('Alice has Bob ephemeral?', aliceState.theirEphemeral !== null);
console.log('Alice will ratchet?', false);

// Alice sends first message (no ratchet)
const [aliceMsg1Key, aliceNewSend1] = kdfChainKey(aliceState.sendingChainKey);
aliceState.sendingChainKey = aliceNewSend1;
console.log('Alice sends with ephemeral:', Buffer.from(aliceState.myEphemeral.publicKey).toString('hex').slice(0, 8));

// Bob receives
console.log('\nBob receives:');
console.log('Bob sees Alice ephemeral:', Buffer.from(aliceState.myEphemeral.publicKey).toString('hex').slice(0, 8));
console.log('First time seeing it?', bobState.theirEphemeral === null);

// Bob derives same message key
const [bobMsg1Key, bobNewRecv1] = kdfChainKey(bobState.receivingChainKey);
bobState.receivingChainKey = bobNewRecv1;
console.log('Message keys match?', Buffer.from(aliceMsg1Key).equals(Buffer.from(bobMsg1Key)));

// Bob stores Alice's ephemeral (no ratchet yet)
bobState.theirEphemeral = aliceState.myEphemeral.publicKey;

console.log('\n=== Message 2: Bob → Alice ===');
console.log('Bob has Alice ephemeral?', bobState.theirEphemeral !== null);
console.log('Bob will ratchet?', true);

// Bob performs DH ratchet before sending
const bobNewEphemeral = nacl.box.keyPair();
const bobDH = dh(bobNewEphemeral.secretKey, bobState.theirEphemeral);
const [bobNewRoot, bobNewSendChain] = kdfRootKey(bobState.rootKey, bobDH);

console.log('Bob DH: new_eph × alice_eph');
console.log('  Bob new eph:', Buffer.from(bobNewEphemeral.publicKey).toString('hex').slice(0, 8));
console.log('  Alice eph:', Buffer.from(bobState.theirEphemeral).toString('hex').slice(0, 8));
console.log('  DH output:', Buffer.from(bobDH).toString('hex').slice(0, 8));

bobState.myEphemeral = bobNewEphemeral;
bobState.rootKey = bobNewRoot;
bobState.sendingChainKey = bobNewSendChain;

// Bob derives message key from new chain
const [bobMsg2Key, bobNewSend2] = kdfChainKey(bobState.sendingChainKey);
bobState.sendingChainKey = bobNewSend2;
console.log('Bob sends with new ephemeral:', Buffer.from(bobState.myEphemeral.publicKey).toString('hex').slice(0, 8));

// Alice receives
console.log('\nAlice receives:');
console.log('Alice sees Bob ephemeral:', Buffer.from(bobState.myEphemeral.publicKey).toString('hex').slice(0, 8));
console.log('First time seeing it?', aliceState.theirEphemeral === null);

// Alice stores Bob's ephemeral (first time, no ratchet)
aliceState.theirEphemeral = bobState.myEphemeral.publicKey;

// Alice should use INITIAL receiving chain (no ratchet yet)
const [aliceMsg2Key, aliceNewRecv2] = kdfChainKey(aliceState.receivingChainKey);
aliceState.receivingChainKey = aliceNewRecv2;

console.log('\nMessage keys for Bob → Alice:');
console.log('Bob sent with:', Buffer.from(bobMsg2Key).toString('hex').slice(0, 8));
console.log('Alice receives with:', Buffer.from(aliceMsg2Key).toString('hex').slice(0, 8));
console.log('Keys match?', Buffer.from(bobMsg2Key).equals(Buffer.from(aliceMsg2Key)));

if (!Buffer.from(bobMsg2Key).equals(Buffer.from(aliceMsg2Key))) {
  console.log('\n❌ PROBLEM: Bob ratcheted his sending chain but Alice is still using initial receiving chain');
  console.log('Bob used new chain from ratchet, Alice needs to also ratchet to match!');
}