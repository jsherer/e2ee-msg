const nacl = require('tweetnacl');

function generateKeyPair() {
  const { publicKey, secretKey } = nacl.box.keyPair();
  return { publicKey: publicKey.slice(0, 32), secretKey: secretKey.slice(0, 32) };
}

function dh(privateKey, publicKey) {
  return nacl.box.before(publicKey, privateKey);
}

function concat(a, b) {
  const result = new Uint8Array(a.length + b.length);
  result.set(a, 0);
  result.set(b, a.length);
  return result;
}

function kdfChainKey(chainKey) {
  const messageKeyInput = concat(chainKey, new Uint8Array([0x01]));
  const chainKeyInput = concat(chainKey, new Uint8Array([0x02]));
  
  const messageKey = nacl.hash(messageKeyInput).slice(0, 32);
  const nextChainKey = nacl.hash(chainKeyInput).slice(0, 32);
  
  return [messageKey, nextChainKey];
}

// Test
const alice = nacl.box.keyPair();
const bob = nacl.box.keyPair();

// Alice initializes
const aliceShared = dh(alice.secretKey, bob.publicKey);
const aliceHashed = nacl.hash(aliceShared);
const aliceRootKey = aliceHashed.slice(0, 32);
const aliceChainKey = aliceHashed.slice(32, 64);

// Bob initializes  
const bobShared = dh(bob.secretKey, alice.publicKey);
const bobHashed = nacl.hash(bobShared);
const bobRootKey = bobHashed.slice(0, 32);
const bobChainKey = bobHashed.slice(32, 64);

console.log('Shared secrets equal?', Buffer.from(aliceShared).equals(Buffer.from(bobShared)));
console.log('Root keys equal?', Buffer.from(aliceRootKey).equals(Buffer.from(bobRootKey)));
console.log('Chain keys equal?', Buffer.from(aliceChainKey).equals(Buffer.from(bobChainKey)));

// Alice encrypts
const [aliceMessageKey] = kdfChainKey(aliceChainKey);
const plaintext = new TextEncoder().encode('Hello Bob!');
const nonce = nacl.randomBytes(24);
const encrypted = nacl.secretbox(plaintext, nonce, aliceMessageKey);

console.log('Encrypted length:', encrypted.length);

// Bob decrypts
const [bobMessageKey] = kdfChainKey(bobChainKey);
console.log('Message keys equal?', Buffer.from(aliceMessageKey).equals(Buffer.from(bobMessageKey)));

const decrypted = nacl.secretbox.open(encrypted, nonce, bobMessageKey);
console.log('Decrypted:', decrypted ? new TextDecoder().decode(decrypted) : 'FAILED');