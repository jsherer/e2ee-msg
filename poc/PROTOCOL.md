# The PRP-Cap Key Agreement Protocol

**Revision 1, 2025-01-01**  
**Authors:** [Your Name]

---

## Table of Contents
1. [Introduction](#1-introduction)  
2. [Preliminaries](#2-preliminaries)  
   - [2.1. PRP-Cap parameters](#21-prp-cap-parameters)  
   - [2.2. Cryptographic notation](#22-cryptographic-notation)  
   - [2.3. Roles](#23-roles)  
   - [2.4. Keys](#24-keys)  
3. [The PRP-Cap protocol](#3-the-prp-cap-protocol)  
   - [3.1. Overview](#31-overview)  
   - [3.2. Publishing epoch parameters](#32-publishing-epoch-parameters)  
   - [3.3. Sending the initial message](#33-sending-the-initial-message)  
   - [3.4. Receiving the initial message](#34-receiving-the-initial-message)  
   - [3.5. Handling simultaneous initiation](#35-handling-simultaneous-initiation)  
4. [Security considerations](#4-security-considerations)  
   - [4.1. Authentication](#41-authentication)  
   - [4.2. Protocol replay](#42-protocol-replay)  
   - [4.3. Forward secrecy](#43-forward-secrecy)  
   - [4.4. Deniability](#44-deniability)  
   - [4.5. Key compromise](#45-key-compromise)  
   - [4.6. Serverless operation](#46-serverless-operation)  
   - [4.7. Identity binding](#47-identity-binding)  
   - [4.8. Epoch management](#48-epoch-management)  
5. [IPR](#5-ipr)  
6. [Acknowledgements](#6-acknowledgements)  
7. [References](#7-references)  

---

## 1. Introduction

This document describes the "PRP-Cap" (or "Pseudorandom Permutation Capability") key agreement protocol. PRP-Cap establishes a shared secret key between two parties who mutually authenticate each other based on public keys. PRP-Cap provides forward secrecy, cryptographic deniability, and true zero round-trip time (0-RTT) message delivery.

PRP-Cap is designed for fully asynchronous, serverless settings where two users ("Alice" and "Bob") may never be online simultaneously and no third-party infrastructure is available. Unlike X3DH, PRP-Cap achieves forward-secure 0-RTT without requiring a server or pre-key exhaustion management.

The key innovation is the use of pseudorandom permutation capabilities: instead of storing individual pre-keys, recipients publish epoch parameters that enable senders to derive unlimited ephemeral receiver keys that appear random but are deterministically computable.

---

## 2. Preliminaries

### 2.1. PRP-Cap parameters

An application using PRP-Cap must decide on several parameters:

| Name  | Definition |
|-------|------------|
| curve | X25519 for DH operations, Ed25519 for point arithmetic |
| hash  | SHA-512 (512-bit hash function) |
| info  | An ASCII string identifying the application |
| epoch_duration | Time period for epoch keys (e.g., 2592000 seconds = 30 days) |
| merge_window | Time window for detecting simultaneous initiation (e.g., 30 seconds) |

For this specification, we fix:
- curve = X25519/Ed25519
- hash = SHA-512
- info = `"PRP-Cap-v1"`

Applications must also define:
- `Encode(PK)`: Function to encode elliptic curve points as byte sequences
- `KDF(KM)`: Key derivation using HKDF-SHA512

### 2.2. Cryptographic notation

- `X || Y`: Concatenation of byte sequences X and Y
- `DH(PK1, PK2)`: X25519 Diffie-Hellman output
- `Sig(PK, M)`: Ed25519 signature of M verifiable with public key PK
- `KDF(KM)`: HKDF-SHA512 output with salt = zeroes, info = application-specific
- `H(M)`: SHA-512 hash of message M
- `H_to_scalar(M)`: Hash M and reduce modulo curve order to produce scalar
- `G`: Ed25519 base point
- `s·G`: Scalar multiplication of base point G by scalar s
- `A + B`: Ed25519 point addition

### 2.3. Roles

- **Alice**: The party initiating the key agreement and sending the first encrypted message
- **Bob**: The party who has published epoch parameters and receives the initial message
- **No Server**: Unlike X3DH, PRP-Cap operates without any third-party infrastructure

### 2.4. Keys

PRP-Cap uses the following elliptic curve public keys:

| Name | Definition | Lifetime |
|------|-------------|----------|
| IKA  | Alice's identity key | Long-term |
| EKA  | Alice's ephemeral key | Single use |
| IKB  | Bob's identity key | Long-term |
| AB   | Bob's first epoch parameter (s1·G) | Epoch duration |
| BB   | Bob's second epoch parameter (s2·G) | Epoch duration |
| Vi   | PRP capability point for index i | Derived per message |

Private keys:

| Name | Definition | Security |
|------|-------------|----------|
| s1B  | Bob's first epoch scalar | Retained during epoch |
| s2B  | Bob's second epoch scalar | **DELETED at epoch end** |
| vi   | Private key for Vi | Computable only by Bob |

---

## 3. The PRP-Cap protocol

### 3.1. Overview

The PRP-Cap protocol has three phases:

1. Bob generates and publishes epoch parameters out-of-band
2. Alice fetches Bob's parameters, computes a PRP capability, and sends an initial message
3. Bob processes the initial message to establish the shared secret

Additionally, PRP-Cap handles simultaneous initiation:

4. If both parties send initial messages simultaneously, they merge the resulting shared secrets

### 3.2. Publishing epoch parameters

Bob generates epoch parameters:

1. Generate random 32-byte scalars `s1` and `s2`
2. Clamp scalars to valid Curve25519 format:
   - Clear bits 0, 1, 2, and 255
   - Set bit 254
3. Compute public parameters:
   - `AB = s1·G`
   - `BB = s2·G`
4. Create epoch bundle:
   ```
   epoch_bundle = {
     identity_key: IKB,
     epoch_A: AB,
     epoch_B: BB,
     valid_from: timestamp,
     valid_until: timestamp + epoch_duration,
     signature: Sig(IKB, Encode(AB) || Encode(BB) || valid_from || valid_until)
   }
   ```
5. Share epoch bundle out-of-band (e.g., QR code, in-person exchange)

**Security**: Bob MUST securely delete `s2` at `valid_until` time. This deletion provides forward secrecy.

### 3.3. Sending the initial message

Alice sends an initial message to Bob:

1. Verify Bob's epoch bundle signature
2. Select an index `i` (random 64-bit integer)
3. Generate ephemeral key pair:
   - Generate random 32-byte scalar `e`
   - Clamp scalar to valid format
   - Compute `EKA = e·G`
4. Compute PRP capability:
   ```
   ti = H_to_scalar(info || Encode(i) || Encode(AB) || Encode(BB))
   Vi = AB + ti·BB
   ```
5. Convert Vi from Ed25519 to X25519 format for DH
6. Compute shared secret:
   ```
   DH1 = DH(IKA, IKB)
   DH2 = DH(EKA, IKB)  
   DH3 = DH(EKA, Vi)
   SK = KDF(DH1 || DH2 || DH3)
   ```
7. Encrypt initial message:
   ```
   AD = Encode(IKA) || Encode(IKB) || Encode(EKA) || Encode(Vi) || Encode(i)
   ciphertext = AEAD_Encrypt(SK, plaintext, AD)
   ```
8. Create and send initial message:
   ```
   initial_message = {
     sender_identity: IKA,
     ephemeral: EKA,
     capability: Vi,
     index: i,
     ciphertext: ciphertext,
     message_id: random_128_bits,
     signature: Sig(IKA, Encode(EKA) || Encode(Vi) || Encode(i) || ciphertext)
   }
   ```

### 3.4. Receiving the initial message

Bob processes Alice's initial message:

1. Verify signature using `IKA`
2. Verify Vi computation:
   ```
   ti = H_to_scalar(info || Encode(i) || Encode(AB) || Encode(BB))
   expected_Vi = AB + ti·BB
   if Vi ≠ expected_Vi: abort
   ```
3. Compute private key for Vi:
   ```
   vi = s1 + ti·s2
   ```
4. Recompute shared secrets:
   ```
   DH1 = DH(IKB, IKA)
   DH2 = DH(IKB, EKA)
   DH3 = DH(vi, EKA)  
   SK = KDF(DH1 || DH2 || DH3)
   ```
5. Decrypt:
   ```
   AD = Encode(IKA) || Encode(IKB) || Encode(EKA) || Encode(Vi) || Encode(i)
   plaintext = AEAD_Decrypt(SK, ciphertext, AD)
   ```
6. Mark index `i` as used (replay protection)
7. Initialize Double Ratchet with root key = `SK`

### 3.5. Handling simultaneous initiation

When both parties send initial messages within the merge window:

1. **Detection**: Each party maintains pending initiation state:
   ```
   pending_initiations = Map<identity_key, {
     message: initial_message,
     timestamp: time,
     state: "waiting" | "merged"
   }>
   ```

2. **Merge Process**: Upon detecting simultaneous initiation:
   ```
   // Alice has sent to Bob and received from Bob
   DH1 = DH(IKA, IKB)
   DH2a = DH(EKA, IKB)
   DH3a = DH(EKA, Vj_bob)  // Alice's ladder
   DH2b = DH(IKA, EKB)  
   DH3b = DH(vi_alice_private, EKB)  // Bob's ladder
   
   // Canonical ordering
   if Compare(EKA, EKB) < 0:
     SK = KDF(DH1 || DH2a || DH3a || DH2b || DH3b || "DoubleLadder")
   else:
     SK = KDF(DH1 || DH2b || DH3b || DH2a || DH3a || "DoubleLadder")
   ```

3. **State Resolution**: Both parties independently arrive at same `SK`

4. **Advantages**: Double ladder provides stronger forward secrecy as compromise requires both ephemeral secrets or both `s2` values.

---

## 4. Security considerations

### 4.1. Authentication

PRP-Cap provides mutual authentication through:
- Signatures on all messages (proves possession of identity key)
- DH1 term involving both identity keys
- Out-of-band verification of identity keys (QR code exchange)

Parties SHOULD verify identity key fingerprints through a trusted channel before relying on authentication.

### 4.2. Protocol replay

Within an epoch, replay protection requires:
- Maintaining a set of used indices
- Rejecting messages with duplicate `(sender, index)` pairs
- Time-based or counter-based indices can provide natural ordering

Applications MUST implement replay detection at the protocol or application layer.

### 4.3. Forward secrecy

PRP-Cap achieves forward secrecy through:

1. **Ephemeral keys**: Sender's ephemeral secret `e` is never stored
2. **Epoch erasure**: Deleting `s2` at epoch end makes all Vi private keys unrecoverable
3. **Double ladder**: Simultaneous initiation requires compromising both directions

Even with compromise of all identity keys and `s1`, messages remain secure after `s2` deletion.

**Security theorem**: After epoch erasure, recovering past session keys requires either:
- Solving the discrete logarithm problem, or
- Compromising the ephemeral private key (never stored)

### 4.4. Deniability

PRP-Cap provides cryptographic deniability properties:

- **Message deniability**: After key exchange, either party could have created the transcript
- **Participation deniability**: Signatures are on ephemeral data that could be forged after key compromise

However, the initial message signature provides non-repudiation during the protocol run.

### 4.5. Key compromise

Different compromises have different impacts:

| Compromise | Impact | Mitigation |
|------------|--------|------------|
| Identity key | Future impersonation | Regular key rotation, revocation |
| s1 (current) | Can receive current messages | Epoch rotation |
| s2 (current) | Can compute all Vi in epoch | Secure deletion critical |
| s1 + s2 | Full epoch compromise | Limit epoch duration |
| Old s1 (s2 deleted) | No impact | Forward secrecy preserved |
| Ephemeral key | Single session compromise | Never stored |

### 4.6. Serverless operation

Unlike X3DH, PRP-Cap operates without servers, providing:

**Advantages**:
- No server trust required
- No availability dependence  
- No metadata leakage
- True peer-to-peer security

**Trade-offs**:
- Epoch parameters must be exchanged out-of-band
- No prekey replenishment service
- Direct peer availability needed for non-0-RTT messages

### 4.7. Identity binding

PRP-Cap binds identities through:

1. Signatures over all protocol messages
2. Identity keys included in KDF inputs
3. Out-of-band verification (QR codes)

This prevents unknown key-share attacks and identity misbinding.

### 4.8. Epoch management

Secure epoch management is critical:

**Requirements**:
- Secure generation of `s1`, `s2` with proper randomness
- Cryptographic erasure of `s2` at epoch end
- No reuse of epoch parameters across different peers
- Overlap period during epoch transition

**Rotation triggers**:
- Scheduled (every 30 days)
- After suspected compromise
- Before high-risk events
- After N messages (configurable)

**In-band rotation** (for established sessions):
```
rotation_message = {
  new_epoch: {A_new, B_new, valid_from, valid_until},
  old_epoch_id: H(A_old || B_old),
  signature: Sig(IK, Encode(A_new) || Encode(B_new) || valid_from || old_epoch_id)
}
```

---

## 5. IPR

This document is placed in the public domain.

---

## 6. Acknowledgements

The PRP-Cap protocol builds upon ideas from:
- The Signal Protocol (Moxie Marlinspike, Trevor Perrin)
- X3DH key agreement (Open Whisper Systems)
- Academic work on forward secrecy and 0-RTT protocols

Special thanks to the cryptographic community for foundational work on elliptic curves, authenticated key exchange, and secure messaging protocols.

---

## 7. References

1. T. Perrin, M. Marlinspike, "The X3DH Key Agreement Protocol", 2016
2. T. Perrin, M. Marlinspike, "The Double Ratchet Algorithm", 2016  
3. D. J. Bernstein, "Curve25519: new Diffie-Hellman speed records", 2006
4. D. J. Bernstein et al., "Ed25519: high-speed high-security signatures", 2011
5. H. Krawczyk, "Cryptographic Extraction and Key Derivation: HKDF", RFC 5869
6. P. Rogaway, "Authenticated-encryption with associated-data", 2002
7. N. Borisov et al., "Off-the-record Communication, or, Why Not To Use PGP", 2004
8. C. Kudla, K. Paterson, "Modular Security Proofs for Key Agreement Protocols", 2005
9. B. Dowling et al., "A Cryptographic Analysis of the TLS 1.3 Handshake Protocol", 2021
10. Signal Specification, "XEdDSA and VXEdDSA Signature Schemes", 2016