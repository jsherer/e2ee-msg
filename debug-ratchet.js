const nacl = require('tweetnacl');

// Minimal ratchet implementation for debugging
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

// Test scenario
const alice = nacl.box.keyPair();
const bob = nacl.box.keyPair();

// Initialize both sides
const aliceShared = dh(alice.secretKey, bob.publicKey);
const bobShared = dh(bob.secretKey, alice.publicKey);
console.log('Initial shared secrets equal?', Buffer.from(aliceShared).equals(Buffer.from(bobShared)));

const aliceHashedSecret = nacl.hash(aliceShared);
const bobHashedSecret = nacl.hash(bobShared);

let aliceState = {
  rootKey: aliceHashedSecret.slice(0, 32),
  sendingChainKey: aliceHashedSecret.slice(32, 64),
  receivingChainKey: new Uint8Array(aliceHashedSecret.slice(32, 64)),
  myEphemeral: nacl.box.keyPair(),
  theirEphemeral: null
};

let bobState = {
  rootKey: bobHashedSecret.slice(0, 32),
  sendingChainKey: bobHashedSecret.slice(32, 64),
  receivingChainKey: new Uint8Array(bobHashedSecret.slice(32, 64)),
  myEphemeral: nacl.box.keyPair(),
  theirEphemeral: null
};

console.log('\nInitial state:');
console.log('Alice root key:', Buffer.from(aliceState.rootKey).toString('hex').slice(0, 16) + '...');
console.log('Bob root key:  ', Buffer.from(bobState.rootKey).toString('hex').slice(0, 16) + '...');
console.log('Root keys equal?', Buffer.from(aliceState.rootKey).equals(Buffer.from(bobState.rootKey)));

// Alice sends first message (no DH ratchet yet - Bob's ephemeral unknown)
console.log('\n1. Alice -> Bob (first message):');
const [aliceMsg1Key, aliceNewSendChain] = kdfChainKey(aliceState.sendingChainKey);
aliceState.sendingChainKey = aliceNewSendChain;
console.log('Alice uses message key from initial sending chain');
console.log('Alice includes her ephemeral:', Buffer.from(aliceState.myEphemeral.publicKey).toString('hex').slice(0, 16) + '...');

// Bob receives (sees Alice's ephemeral for first time)
console.log('\n2. Bob receives from Alice:');
console.log('Bob sees Alice ephemeral, but decrypts with initial receiving chain first');
const [bobMsg1Key, bobNewRecvChain] = kdfChainKey(bobState.receivingChainKey);
bobState.receivingChainKey = bobNewRecvChain;
console.log('Message keys match?', Buffer.from(aliceMsg1Key).equals(Buffer.from(bobMsg1Key)));

// Bob performs DH ratchet after decrypting
console.log('Bob performs DH ratchet with Alice ephemeral');
bobState.theirEphemeral = aliceState.myEphemeral.publicKey;
const bobDH1 = dh(bobState.myEphemeral.secretKey, bobState.theirEphemeral);
const [bobNewRoot1, bobNewRecvChain2] = kdfRootKey(bobState.rootKey, bobDH1);
bobState.rootKey = bobNewRoot1;
// Don't update receiving chain - already used it

// Bob sends reply (WITH DH ratchet - has Alice's ephemeral)
console.log('\n3. Bob -> Alice (reply):');
console.log('Bob has Alice ephemeral, so performs DH ratchet before sending');
const bobNewEphemeral = nacl.box.keyPair();
const bobDH2 = dh(bobState.myEphemeral.secretKey, bobState.theirEphemeral);
const [bobNewRoot2, bobNewSendChain] = kdfRootKey(bobState.rootKey, bobDH2);
bobState.rootKey = bobNewRoot2;
bobState.sendingChainKey = bobNewSendChain;
bobState.myEphemeral = bobNewEphemeral;

const [bobMsg2Key, bobNewSendChain2] = kdfChainKey(bobState.sendingChainKey);
bobState.sendingChainKey = bobNewSendChain2;
console.log('Bob sends with new ephemeral:', Buffer.from(bobState.myEphemeral.publicKey).toString('hex').slice(0, 16) + '...');

// Alice receives Bob's reply
console.log('\n4. Alice receives from Bob:');
console.log('Alice sees Bob ephemeral for first time');
aliceState.theirEphemeral = bobState.myEphemeral.publicKey;

// Alice needs to figure out what key to use
// Bob performed DH ratchet, so Alice needs to as well
console.log('Alice performs DH ratchet with Bob ephemeral');
const aliceDH1 = dh(aliceState.myEphemeral.secretKey, aliceState.theirEphemeral);
const [aliceNewRoot1, aliceNewRecvChain] = kdfRootKey(aliceState.rootKey, aliceDH1);
aliceState.rootKey = aliceNewRoot1;
aliceState.receivingChainKey = aliceNewRecvChain;

const [aliceMsg2Key, aliceNewRecvChain2] = kdfChainKey(aliceState.receivingChainKey);
aliceState.receivingChainKey = aliceNewRecvChain2;

console.log('\nDo message keys match for Bob->Alice?');
console.log('Bob sent with key:   ', Buffer.from(bobMsg2Key).toString('hex').slice(0, 16) + '...');
console.log('Alice receives with: ', Buffer.from(aliceMsg2Key).toString('hex').slice(0, 16) + '...');
console.log('Keys match?', Buffer.from(bobMsg2Key).equals(Buffer.from(aliceMsg2Key)));