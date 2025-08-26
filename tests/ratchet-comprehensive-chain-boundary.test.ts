import { initializeRatchet, ratchetEncrypt, ratchetDecrypt } from '../src/utils/ratchet';
import * as nacl from 'tweetnacl';

describe('Ratchet Protocol - Comprehensive Chain Boundary Test', () => {
  it('should handle complex out-of-order delivery across chain boundaries with detailed verification', () => {
    // Setup
    const aliceIdentity = nacl.box.keyPair();
    const bobIdentity = nacl.box.keyPair();

    let aliceState = initializeRatchet(aliceIdentity, bobIdentity.publicKey);
    let bobState = initializeRatchet(bobIdentity, aliceIdentity.publicKey);

    // Alice sends messages 1 and 2 in her initial chain
    const msg1 = new TextEncoder().encode('Alice 1');
    const msg2 = new TextEncoder().encode('Alice 2');
    const [enc1, aliceState2] = ratchetEncrypt(aliceState, msg1);
    const [enc2, aliceState3] = ratchetEncrypt(aliceState2, msg2);
    
    // Verify Alice's state after sending 2 messages
    expect(aliceState3.sendMessageCounter).toBe(2);
    expect(aliceState3.previousSendCounter).toBe(0);

    // Bob receives first message and replies (triggers DH ratchet)
    const [dec1, bobState2] = ratchetDecrypt(bobState, enc1);
    expect(new TextDecoder().decode(dec1)).toBe('Alice 1');
    expect(bobState2.receiveMessageCounter).toBe(1);

    const msgB = new TextEncoder().encode('Bob reply');
    const [encB, bobState3] = ratchetEncrypt(bobState2, msgB);
    
    // Verify Bob performed a DH ratchet
    expect(bobState3.sendMessageCounter).toBe(1);
    expect(bobState3.previousSendCounter).toBe(0);

    // Alice receives Bob's reply and sends more messages in a new chain
    const [decB, aliceState4] = ratchetDecrypt(aliceState3, encB);
    expect(new TextDecoder().decode(decB)).toBe('Bob reply');
    
    // Verify Alice's state before sending in new chain
    expect(aliceState4.sendMessageCounter).toBe(2); // Still 2 from her previous sends
    expect(aliceState4.theirLatestEphemeralPublicKey).not.toBeNull(); // Has Bob's ephemeral
    
    const msg3 = new TextEncoder().encode('Alice 3 (new chain)');
    const msg4 = new TextEncoder().encode('Alice 4 (new chain)');
    const [enc3, aliceState5] = ratchetEncrypt(aliceState4, msg3);
    
    // Verify Alice performed a DH ratchet for sending
    expect(aliceState5.sendMessageCounter).toBe(1); // Reset to 1 after sending first message in new chain
    expect(aliceState5.previousSendCounter).toBe(2); // Correctly saved her previous count
    
    const [enc4, aliceState6] = ratchetEncrypt(aliceState5, msg4);
    expect(aliceState6.sendMessageCounter).toBe(2); // Second message in new chain
    expect(aliceState6.previousSendCounter).toBe(2); // Still the same

    // TEST THE CRITICAL SCENARIO: Bob receives message 4 first (out of order)
    // This skips message 2 from the old chain and message 3 from the new chain
    
    // Parse message 4 header to verify it has correct metadata
    const msg4PrevCounter = new DataView(enc4.buffer, enc4.byteOffset + 33, 4).getUint32(0, false);
    const msg4Counter = new DataView(enc4.buffer, enc4.byteOffset + 37, 4).getUint32(0, false);
    expect(msg4PrevCounter).toBe(2); // Alice sent 2 messages in previous chain
    expect(msg4Counter).toBe(1); // This is message 1 in new chain (0-indexed)

    const [dec4, bobState4] = ratchetDecrypt(bobState3, enc4);
    expect(new TextDecoder().decode(dec4)).toBe('Alice 4 (new chain)');
    
    // Verify Bob has properly stored skipped keys and chain state
    expect(bobState4.skippedMessageKeys.size).toBeGreaterThan(0);
    expect(bobState4.previousReceivingChains.size).toBe(1); // Old chain saved

    // TEST: Bob can still decrypt message 2 from the old chain
    const [dec2, bobState5] = ratchetDecrypt(bobState4, enc2);
    expect(new TextDecoder().decode(dec2)).toBe('Alice 2');
    
    // Verify the skipped key was used and removed
    expect(bobState5.skippedMessageKeys.size).toBeLessThan(bobState4.skippedMessageKeys.size);

    // TEST: Bob can still decrypt message 3 from the new chain
    const [dec3, bobState6] = ratchetDecrypt(bobState5, enc3);
    expect(new TextDecoder().decode(dec3)).toBe('Alice 3 (new chain)');
    
    // All messages successfully decrypted in wrong order!
  });
});