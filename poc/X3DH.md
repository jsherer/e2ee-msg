# The X3DH Key Agreement Protocol

**Revision 1, 2016-11-04** [PDF]  
**Authors:** Moxie Marlinspike, Trevor Perrin (editor)

---

## Table of Contents
1. [Introduction](#1-introduction)  
2. [Preliminaries](#2-preliminaries)  
   - [2.1. X3DH parameters](#21-x3dh-parameters)  
   - [2.2. Cryptographic notation](#22-cryptographic-notation)  
   - [2.3. Roles](#23-roles)  
   - [2.4. Keys](#24-keys)  
3. [The X3DH protocol](#3-the-x3dh-protocol)  
   - [3.1. Overview](#31-overview)  
   - [3.2. Publishing keys](#32-publishing-keys)  
   - [3.3. Sending the initial message](#33-sending-the-initial-message)  
   - [3.4. Receiving the initial message](#34-receiving-the-initial-message)  
4. [Security considerations](#4-security-considerations)  
   - [4.1. Authentication](#41-authentication)  
   - [4.2. Protocol replay](#42-protocol-replay)  
   - [4.3. Replay and key reuse](#43-replay-and-key-reuse)  
   - [4.4. Deniability](#44-deniability)  
   - [4.5. Signatures](#45-signatures)  
   - [4.6. Key compromise](#46-key-compromise)  
   - [4.7. Server trust](#47-server-trust)  
   - [4.8. Identity binding](#48-identity-binding)  
5. [IPR](#5-ipr)  
6. [Acknowledgements](#6-acknowledgements)  
7. [References](#7-references)  

---

## 1. Introduction
This document describes the "X3DH" (or "Extended Triple Diffie-Hellman") key agreement protocol. X3DH establishes a shared secret key between two parties who mutually authenticate each other based on public keys. X3DH provides forward secrecy and cryptographic deniability.

X3DH is designed for asynchronous settings where one user ("Bob") is offline but has published some information to a server. Another user ("Alice") wants to use that information to send encrypted data to Bob, and also establish a shared secret key for future communication.

---

## 2. Preliminaries

### 2.1. X3DH parameters
An application using X3DH must decide on several parameters:

| Name  | Definition |
|-------|------------|
| curve | X25519 or X448 |
| hash  | A 256 or 512-bit hash function (e.g., SHA-256 or SHA-512) |
| info  | An ASCII string identifying the application |

Example: curve = X25519, hash = SHA-512, info = `"MyProtocol"`.

Applications must also define an `Encode(PK)` function to encode X25519/X448 public keys.

---

### 2.2. Cryptographic notation
- `X || Y`: concatenation of byte sequences.  
- `DH(PK1, PK2)`: output of Elliptic Curve Diffie-Hellman using PK1, PK2.  
- `Sig(PK, M)`: XEdDSA signature of `M` verifying under PK.  
- `KDF(KM)`: 32-byte HKDF output with specific domain separation rules.  

---

### 2.3. Roles
- **Alice:** initiates key agreement and sends encrypted data.  
- **Bob:** publishes prekeys and later processes Alice’s message.  
- **Server:** stores prekeys and messages; some trust is required.  

---

### 2.4. Keys
X3DH uses the following elliptic curve public keys:

| Name | Definition |
|------|-------------|
| IKA  | Alice's identity key |
| EKA  | Alice's ephemeral key |
| IKB  | Bob's identity key |
| SPKB | Bob's signed prekey |
| OPKB | Bob's one-time prekey |

---

## 3. The X3DH protocol

### 3.1. Overview
1. Bob publishes identity + prekeys to the server.  
2. Alice fetches Bob’s "prekey bundle" and sends an initial message.  
3. Bob processes the initial message.  

---

### 3.2. Publishing keys
Bob uploads:
- Identity key `IKB`  
- Signed prekey `SPKB`  
- Signature `Sig(IKB, Encode(SPKB))`  
- One-time prekeys `(OPKB1, OPKB2, …)`  

Keys are periodically rotated for forward secrecy.

---

### 3.3. Sending the initial message
Alice fetches Bob’s prekey bundle.  
- Verifies signature.  
- Generates ephemeral key `EKA`.  
- Computes shared secrets (`DH1..DH4`) depending on presence of one-time prekey.  
- Derives session key `SK = KDF(...)`.  
- Sends message containing:  
  - `IKA`, `EKA`  
  - Prekey identifiers  
  - Initial ciphertext (AEAD, keyed by `SK`).  

---

### 3.4. Receiving the initial message
Bob:  
- Extracts `IKA`, `EKA`.  
- Recomputes `DH1..DH4`, derives `SK`.  
- Builds associated data `AD = Encode(IKA) || Encode(IKB)`.  
- Attempts decryption.  
- If success: protocol complete; one-time prekey is deleted.  

---

## 4. Security considerations

### 4.1. Authentication
Parties should compare key fingerprints (e.g., manually or via QR code).

### 4.2. Protocol replay
Without one-time prekeys, messages may be replayed. Mitigation: post-X3DH ratchet protocols.

### 4.3. Replay and key reuse
Replays may cause reuse of the same `SK`. Post-X3DH protocols **MUST** randomize keys.

### 4.4. Deniability
X3DH provides deniability similar to OTR, with limitations in asynchronous settings.

### 4.5. Signatures
Necessary to prevent malicious servers from substituting keys. Avoid identity-key signatures for authentication.

### 4.6. Key compromise
- Compromise of identity key = impersonation.  
- Prekey compromise impacts security of older/newer sessions.  
- Frequent rotation of prekeys + ratcheting protocols mitigate risks.  

### 4.7. Server trust
A malicious server can block/delay messages or withhold one-time prekeys.

### 4.8. Identity binding
Attackers may misbind identities ("unknown key share"). Extra identifiers in AD may help but trade-offs exist.

---

## 5. IPR
This document is placed in the public domain.

---

## 6. Acknowledgements
- X3DH: Moxie Marlinspike & Trevor Perrin.  
- Triple DH: Caroline Kudla & Kenny Paterson.  
- Thanks: Mike Hamburg, Nik Unger, Matthew Green, Tom Ritter, Joseph Bonneau, Benedikt Schmidt.  

---

## 7. References
1. RFC 7748: [Elliptic Curves for Security](http://www.ietf.org/rfc/rfc7748.txt)  
2. T. Perrin, *The XEdDSA and VXEdDSA Signature Schemes*, 2016.  
3. RFC 5869: [HKDF](http://www.ietf.org/rfc/rfc5869.txt)  
4. P. Rogaway, *Authenticated-encryption with Associated-data*, 2002.  
5. T. Perrin, *The Double Ratchet Algorithm (work in progress)*, 2016.  
6. N. Borisov et al., *Off-the-record Communication*, 2004.  
7. N. Unger, I. Goldberg, *Deniable Key Exchanges for Secure Messaging*, 2015.  
8. C. Kudla, K. Paterson, *Modular Security Proofs for Key Agreement Protocols*, 2005.  
9. S. Blake-Wilson et al., *Key agreement protocols and their security analysis*, 1997.  
10. C. Cremers, M. Feltz, *One-round Strongly Secure Key Exchange*, 2011.  
11. J. P. Degabriele et al., *On the Joint Security of Encryption and Signature in EMV*, 2011.  
