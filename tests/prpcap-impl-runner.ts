#!/usr/bin/env tsx
/**
 * Test runner for PRP-Cap implementation
 * Run with: npx tsx tests/prpcap-impl-runner.ts
 */

import {
  initializeEd25519,
  generatePRPCapEpoch,
  computeVi,
  compute_vi,
  ed25519DH,
  createPRPCapMessage,
  processPRPCapMessage,
  testPRPCapConvergence,
  bytesToNumberLE,
  numberToBytesLE
} from '../src/utils/prpcap-impl';

// Test helpers
let passed = 0;
let failed = 0;

function test(name: string, fn: () => Promise<void>) {
  return fn()
    .then(() => {
      console.log(`✅ ${name}`);
      passed++;
    })
    .catch((error) => {
      console.log(`❌ ${name}`);
      console.error(`   ${error.message}`);
      failed++;
    });
}

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(message);
  }
}

function assertArraysEqual(a: Uint8Array, b: Uint8Array, message: string) {
  if (a.length !== b.length) {
    throw new Error(`${message}: Different lengths ${a.length} vs ${b.length}`);
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      throw new Error(`${message}: Arrays differ at index ${i}`);
    }
  }
}

// Main test runner
async function runTests() {
  const { sha512 } = await import('@noble/hashes/sha2');
  
  console.log('🧪 PRP-Cap Implementation Tests\n');

  await test('Initialize Ed25519 library', async () => {
    await initializeEd25519();
    // If we get here without error, it worked
  });

  await test('Generate epoch parameters', async () => {
    const epoch = await generatePRPCapEpoch();
    assert(epoch.A.length === 32, 'A should be 32 bytes');
    assert(epoch.B.length === 32, 'B should be 32 bytes');
    assert(epoch.s1.length === 32, 's1 should be 32 bytes');
    assert(epoch.s2.length === 32, 's2 should be 32 bytes');
  });

  await test('Key convergence: DH(e, V_i) = DH(v_i, E)', async () => {
    const epoch = await generatePRPCapEpoch();
    
    // Generate ephemeral
    const ed = await import('@noble/ed25519');
    const ephemeralSeed = ed.utils.randomPrivateKey();
    const ephemeralHash = sha512(ephemeralSeed);
    const ephemeralScalar = ephemeralHash.slice(0, 32);
    ephemeralScalar[0] &= 248;
    ephemeralScalar[31] &= 63;
    ephemeralScalar[31] |= 64;
    
    const ephemeralBigint = ed.etc.mod(bytesToNumberLE(ephemeralScalar), ed.CURVE.n);
    const ephemeralPublic = ed.Point.BASE.multiply(ephemeralBigint).toRawBytes();
    
    const index = 42;
    
    // Alice computes V_i
    const V_i = await computeVi(epoch.A, epoch.B, index);
    
    // Bob computes v_i
    const v_i = await compute_vi(epoch.s1, epoch.s2, epoch.A, epoch.B, index);
    
    // Alice: DH(e, V_i)
    const aliceShared = await ed25519DH(ephemeralScalar, V_i);
    const aliceSecret = sha512(aliceShared).slice(0, 32);
    
    // Bob: DH(v_i, E)
    const bobShared = await ed25519DH(v_i, ephemeralPublic);
    const bobSecret = sha512(bobShared).slice(0, 32);
    
    assertArraysEqual(aliceSecret, bobSecret, 'Shared secrets should match');
  });

  await test('Multiple indices converge', async () => {
    const epoch = await generatePRPCapEpoch();
    const ed = await import('@noble/ed25519');
  
  const ephemeralSeed = ed.utils.randomPrivateKey();
  const ephemeralHash = sha512(ephemeralSeed);
  const ephemeralScalar = ephemeralHash.slice(0, 32);
  ephemeralScalar[0] &= 248;
  ephemeralScalar[31] &= 63;
  ephemeralScalar[31] |= 64;
  
  const ephemeralBigint = ed.etc.mod(bytesToNumberLE(ephemeralScalar), ed.CURVE.n);
  const ephemeralPublic = ed.Point.BASE.multiply(ephemeralBigint).toRawBytes();
  
  const indices = [0, 1, 42, 999, 2147483647];
  
  for (const index of indices) {
    const V_i = await computeVi(epoch.A, epoch.B, index);
    const v_i = await compute_vi(epoch.s1, epoch.s2, epoch.A, epoch.B, index);
    
    const aliceShared = await ed25519DH(ephemeralScalar, V_i);
    const aliceSecret = sha512(aliceShared).slice(0, 32);
    
    const bobShared = await ed25519DH(v_i, ephemeralPublic);
    const bobSecret = sha512(bobShared).slice(0, 32);
    
    assertArraysEqual(aliceSecret, bobSecret, `Index ${index} should converge`);
    }
  });

  await test('Message encryption and decryption', async () => {
  const epoch = await generatePRPCapEpoch();
  const plaintext = new TextEncoder().encode('Test message for PRP-Cap');
  
  const message = await createPRPCapMessage(
    plaintext,
    epoch.A,
    epoch.B,
    123
  );
  
  assert(message.ephemeralPublic.length === 32, 'Ephemeral public should be 32 bytes');
  assert(message.index === 123, 'Index should match');
  assert(message.ciphertext.length > 0, 'Should have ciphertext');
  assert(message.nonce.length === 24, 'Nonce should be 24 bytes');
  
  const decrypted = await processPRPCapMessage(message, epoch);
  assert(decrypted !== null, 'Decryption should succeed');
  
  const decryptedText = new TextDecoder().decode(decrypted!);
    assert(decryptedText === 'Test message for PRP-Cap', 'Decrypted text should match');
  });

  await test('0-RTT property', async () => {
  const bobEpoch = await generatePRPCapEpoch();
  
  // Alice only needs Bob's public A and B
  const plaintext = new TextEncoder().encode('0-RTT message');
  const message = await createPRPCapMessage(
    plaintext,
    bobEpoch.A,
    bobEpoch.B,
    999
  );
  
  // Bob can decrypt with his secrets
  const decrypted = await processPRPCapMessage(message, bobEpoch);
  assert(decrypted !== null, 'Should decrypt');
    assert(new TextDecoder().decode(decrypted!) === '0-RTT message', 'Message should match');
  });

  await test('Built-in convergence test', async () => {
  const result = await testPRPCapConvergence();
    assert(result === true, 'Convergence test should pass');
  });

  await test('Wrong epoch fails decryption', async () => {
  const epoch1 = await generatePRPCapEpoch();
  const epoch2 = await generatePRPCapEpoch();
  
  const plaintext = new TextEncoder().encode('Secret');
  const message = await createPRPCapMessage(
    plaintext,
    epoch1.A,
    epoch1.B,
    42
  );
  
  const decrypted = await processPRPCapMessage(message, epoch2);
    assert(decrypted === null, 'Should fail to decrypt with wrong epoch');
  });

  await test('Different V_i for different indices', async () => {
  const epoch = await generatePRPCapEpoch();
  
  const V_1 = await computeVi(epoch.A, epoch.B, 1);
  const V_2 = await computeVi(epoch.A, epoch.B, 2);
  const V_100 = await computeVi(epoch.A, epoch.B, 100);
  
  // Convert to hex for comparison
  const hex1 = Array.from(V_1).map(b => b.toString(16).padStart(2, '0')).join('');
  const hex2 = Array.from(V_2).map(b => b.toString(16).padStart(2, '0')).join('');
  const hex100 = Array.from(V_100).map(b => b.toString(16).padStart(2, '0')).join('');
  
  assert(hex1 !== hex2, 'V_1 should differ from V_2');
  assert(hex1 !== hex100, 'V_1 should differ from V_100');
    assert(hex2 !== hex100, 'V_2 should differ from V_100');
  });

  // Summary
  console.log('\n📊 Results:');
  console.log(`   Passed: ${passed}`);
  console.log(`   Failed: ${failed}`);

  if (failed === 0) {
    console.log('\n🎉 All tests passed! PRP-Cap protocol is working correctly.');
    process.exit(0);
  } else {
    console.log('\n❌ Some tests failed.');
    process.exit(1);
  }
}

// Run the tests
runTests().catch(error => {
  console.error('Test runner failed:', error);
  process.exit(1);
});