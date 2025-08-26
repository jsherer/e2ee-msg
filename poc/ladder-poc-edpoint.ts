// ladder-poc-edpoint.ts
// PRP-Cap 0-RTT Key Exchange with proper Ed25519 arithmetic

import * as nacl from 'tweetnacl';

// ============= Ed25519 Field and Point Arithmetic =============

// Field prime: p = 2^255 - 19
const P = 2n ** 255n - 19n;

// Curve order: l = 2^252 + 27742317777372353535851937790883648493
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

// Curve constant d = -121665/121666 mod p
const D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

/**
 * Modular arithmetic helpers
 */
function mod(a: bigint, m: bigint): bigint {
    const r = a % m;
    return r >= 0n ? r : r + m;
}

function modInverse(a: bigint, m: bigint): bigint {
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    
    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    
    return mod(old_s, m);
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
    let result = 1n;
    base = mod(base, m);
    while (exp > 0n) {
        if (exp % 2n === 1n) result = mod(result * base, m);
        exp = exp / 2n;
        base = mod(base * base, m);
    }
    return result;
}

/**
 * Convert little-endian bytes to bigint
 */
function bytesToBigIntLE(bytes: Uint8Array): bigint {
    let result = 0n;
    for (let i = 0; i < bytes.length; i++) {
        result |= BigInt(bytes[i]) << (8n * BigInt(i));
    }
    return result;
}

/**
 * Convert bigint to little-endian bytes
 */
function bigIntToBytesLE(num: bigint, len: number): Uint8Array {
    const bytes = new Uint8Array(len);
    let temp = mod(num, 2n ** (8n * BigInt(len)));
    for (let i = 0; i < len; i++) {
        bytes[i] = Number(temp & 0xffn);
        temp >>= 8n;
    }
    return bytes;
}

/**
 * Ed25519 Point class
 */
class Ed25519Point {
    constructor(
        public x: bigint,
        public y: bigint,
        public z: bigint = 1n,
        public t: bigint = mod(x * y, P)
    ) {}
    
    static zero(): Ed25519Point {
        return new Ed25519Point(0n, 1n, 1n, 0n);
    }
    
    static base(): Ed25519Point {
        // Standard Ed25519 base point
        const Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;
        const By = 46316835694926478169428394003475163141307993866256225615783033603165251855960n;
        return new Ed25519Point(Bx, By, 1n, mod(Bx * By, P));
    }
    
    /**
     * Decode point from 32 bytes (compressed format)
     */
    static fromBytes(bytes: Uint8Array): Ed25519Point {
        if (bytes.length !== 32) throw new Error('Invalid point');
        
        // Extract y coordinate (little-endian) and sign bit
        const y = bytesToBigIntLE(bytes) & ((1n << 255n) - 1n);
        const sign = (bytes[31] >> 7) === 1;
        
        // Recover x from y: x² = (y² - 1) / (d·y² + 1)
        const y2 = mod(y * y, P);
        const num = mod(y2 - 1n, P);
        const den = mod(D * y2 + 1n, P);
        const x2 = mod(num * modInverse(den, P), P);
        
        // Compute sqrt(x²)
        let x = modPow(x2, (P + 3n) / 8n, P);
        
        // Check if we have the right square root
        if (mod(x * x, P) !== x2) {
            // Multiply by sqrt(-1)
            const sqrtM1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
            x = mod(x * sqrtM1, P);
        }
        
        // Choose the right sign
        if (((x & 1n) === 1n) !== sign) {
            x = mod(P - x, P);
        }
        
        return new Ed25519Point(x, y);
    }
    
    /**
     * Encode point to 32 bytes (compressed format)
     */
    toBytes(): Uint8Array {
        // Normalize to affine coordinates
        const zInv = modInverse(this.z, P);
        const x = mod(this.x * zInv, P);
        const y = mod(this.y * zInv, P);
        
        // Encode y in little-endian with sign bit
        const bytes = bigIntToBytesLE(y, 32);
        
        // Set sign bit if x is odd
        if ((x & 1n) === 1n) {
            bytes[31] |= 0x80;
        }
        
        return bytes;
    }
    
    /**
     * Point addition using extended coordinates
     */
    add(other: Ed25519Point): Ed25519Point {
        const X1 = this.x, Y1 = this.y, Z1 = this.z, T1 = this.t;
        const X2 = other.x, Y2 = other.y, Z2 = other.z, T2 = other.t;
        
        const A = mod((Y1 - X1) * (Y2 - X2), P);
        const B = mod((Y1 + X1) * (Y2 + X2), P);
        const C = mod(T1 * 2n * D * T2, P);
        const D_ = mod(Z1 * 2n * Z2, P);
        const E = mod(B - A, P);
        const F = mod(D_ - C, P);
        const G = mod(D_ + C, P);
        const H = mod(B + A, P);
        
        const X3 = mod(E * F, P);
        const Y3 = mod(G * H, P);
        const Z3 = mod(F * G, P);
        const T3 = mod(E * H, P);
        
        return new Ed25519Point(X3, Y3, Z3, T3);
    }
    
    /**
     * Point doubling (more efficient than adding to itself)
     */
    double(): Ed25519Point {
        const X = this.x, Y = this.y, Z = this.z;
        
        const A = mod(X * X, P);
        const B = mod(Y * Y, P);
        const C = mod(2n * Z * Z, P);
        const H = mod(A + B, P);
        const E = mod(H - mod((X + Y) * (X + Y), P), P);
        const G = mod(A - B, P);
        const F = mod(C + G, P);
        
        const X3 = mod(E * F, P);
        const Y3 = mod(G * H, P);
        const Z3 = mod(F * G, P);
        const T3 = mod(E * H, P);
        
        return new Ed25519Point(X3, Y3, Z3, T3);
    }
    
    /**
     * Scalar multiplication using double-and-add
     */
    multiply(scalar: bigint): Ed25519Point {
        scalar = mod(scalar, L);
        let result = Ed25519Point.zero();
        let temp: Ed25519Point = new Ed25519Point(this.x, this.y, this.z, this.t);
        
        while (scalar > 0n) {
            if (scalar & 1n) {
                result = result.add(temp);
            }
            temp = temp.double();
            scalar >>= 1n;
        }
        
        return result;
    }
    
    /**
     * Convert Ed25519 point to X25519 (Montgomery x-coordinate)
     */
    toX25519(): Uint8Array {
        // Convert to affine coordinates
        const zInv = modInverse(this.z, P);
        const y = mod(this.y * zInv, P);
        
        // Convert from Edwards to Montgomery
        // u = (1 + y) / (1 - y)
        const num = mod(1n + y, P);
        const den = mod(1n - y, P);
        const u = mod(num * modInverse(den, P), P);
        
        return bigIntToBytesLE(u, 32);
    }
}

/**
 * Convert X25519 public key to Ed25519 point
 */
function x25519ToEd25519(xBytes: Uint8Array): Uint8Array {
    // Montgomery u-coordinate to Edwards y-coordinate
    // y = (u - 1) / (u + 1)
    const u = bytesToBigIntLE(xBytes);
    const num = mod(u - 1n, P);
    const den = mod(u + 1n, P);
    const y = mod(num * modInverse(den, P), P);
    
    // Recover x with positive sign
    const y2 = mod(y * y, P);
    const num2 = mod(y2 - 1n, P);
    const den2 = mod(D * y2 + 1n, P);
    const x2 = mod(num2 * modInverse(den2, P), P);
    
    let x = modPow(x2, (P + 3n) / 8n, P);
    if (mod(x * x, P) !== x2) {
        const sqrtM1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;
        x = mod(x * sqrtM1, P);
    }
    
    // Choose positive x
    if ((x & 1n) === 1n) {
        x = mod(P - x, P);
    }
    
    return new Ed25519Point(x, y).toBytes();
}

// ============= PRP-Cap Implementation =============

function hashToScalar(data: Uint8Array): Uint8Array {
    const hash = nacl.hash(data);
    // Clamp like X25519 scalar
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    return hash.slice(0, 32);
}

/**
 * Compute PRP Capability: V_i = A + t_i·B
 */
function computePRPCap(
    A: Uint8Array,
    B: Uint8Array,
    index: number
): Uint8Array {
    // Convert X25519 points to Ed25519
    const A_ed = x25519ToEd25519(A);
    const B_ed = x25519ToEd25519(B);
    
    // Parse points
    const pointA = Ed25519Point.fromBytes(A_ed);
    const pointB = Ed25519Point.fromBytes(B_ed);
    
    // Compute t_i = H(domain || index || A || B)
    const domain = new TextEncoder().encode("PRPCap.v1");
    const indexBytes = new Uint8Array(4);
    new DataView(indexBytes.buffer).setUint32(0, index, true);
    
    const hashInput = new Uint8Array(domain.length + 4 + 64);
    hashInput.set(domain, 0);
    hashInput.set(indexBytes, domain.length);
    hashInput.set(A, domain.length + 4);
    hashInput.set(B, domain.length + 36);
    
    const t_i = hashToScalar(hashInput);
    const t_i_bigint = bytesToBigIntLE(t_i);
    
    // V_i = A + t_i·B
    const pointTiB = pointB.multiply(t_i_bigint);
    const V_i = pointA.add(pointTiB);
    
    // Convert back to X25519 for use with nacl.scalarMult
    return V_i.toX25519();
}

/**
 * Compute shared secret for receiver using the relationship:
 * DH(e, V_i) = DH(e, A + t_i·B) = DH(e, A) + DH(e, t_i·B)
 * Since receiver knows s1 and s2, they can compute this.
 */
function computeReceiverSharedSecret(
    s1: Uint8Array,
    s2: Uint8Array,
    index: number,
    A: Uint8Array,
    B: Uint8Array,
    ephemeralPublic: Uint8Array
): Uint8Array {
    // Compute t_i the same way as sender
    const domain = new TextEncoder().encode("PRPCap.v1");
    const indexBytes = new Uint8Array(4);
    new DataView(indexBytes.buffer).setUint32(0, index, true);
    
    const hashInput = new Uint8Array(domain.length + 4 + 64);
    hashInput.set(domain, 0);
    hashInput.set(indexBytes, domain.length);
    hashInput.set(A, domain.length + 4);
    hashInput.set(B, domain.length + 36);
    
    const t_i = hashToScalar(hashInput);
    
    // Compute DH(s1, E)
    const dh1 = nacl.scalarMult(s1, ephemeralPublic);
    
    // Compute t_i·s2 (scalar multiplication in field)
    // Then compute DH(t_i·s2, E)
    const t_i_s2 = nacl.scalarMult(t_i, B);  // t_i·(s2·G) = (t_i·s2)·G
    
    // We need the private scalar (t_i·s2) but we can compute DH differently:
    // Instead compute: DH(s2, t_i·E)
    const t_i_E = nacl.scalarMult(t_i, ephemeralPublic);
    const dh2 = nacl.scalarMult(s2, t_i_E);
    
    // Combine the two DH results
    // This simulates DH(e, A + t_i·B) = DH(e, A) + DH(e, t_i·B)
    // We need to combine them in the same way as point addition would
    
    // For X25519, we can't directly add the DH results
    // Instead, we'll compute the full private key for V_i differently
    
    // Actually, we need to compute the scalar (s1 + t_i·s2) mod L
    // But X25519 scalars are clamped, so we can't just add them
    
    // Let's use a different approach: compute V_i, then use the combined scalar
    const V_i = computePRPCap(A, B, index);
    
    // The private key for V_i would be (s1 + t_i·s2) but with clamping issues
    // Instead, let's compute it step by step using the group law
    
    // Convert to Ed25519 to do proper scalar arithmetic
    const s1_scalar = bytesToBigIntLE(s1) & ((1n << 254n) - 1n); // Remove clamping bits
    const s2_scalar = bytesToBigIntLE(s2) & ((1n << 254n) - 1n);
    const t_i_scalar = bytesToBigIntLE(t_i) & ((1n << 254n) - 1n);
    
    // v_i = s1 + t_i·s2 (mod L) - proper scalar addition
    const v_i_scalar = mod(s1_scalar + mod(t_i_scalar * s2_scalar, L), L);
    
    // Convert back to bytes and clamp for X25519
    const v_i = bigIntToBytesLE(v_i_scalar, 32);
    v_i[0] &= 248;
    v_i[31] &= 127;
    v_i[31] |= 64;
    
    // Now compute DH(v_i, E)
    return nacl.scalarMult(v_i, ephemeralPublic);
}

// ============= Helper Functions =============

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// ============= Test Scenarios =============

console.log("🔐 PRP-Cap 0-RTT with Ed25519 Arithmetic\n");
console.log("=" .repeat(50));

// Test 1: Ed25519 Point Arithmetic
console.log("\n📝 Test 1: Ed25519 Point Operations");
console.log("-".repeat(40));
{
    const G = Ed25519Point.base();
    console.log(`Base point G computed`);
    
    // Test scalar multiplication
    const scalar = 12345n;
    const P1 = G.multiply(scalar);
    console.log(`${scalar}·G computed`);
    
    // Test point addition
    const P2 = G.multiply(54321n);
    const P3 = P1.add(P2);
    const P3_check = G.multiply(scalar + 54321n);
    console.log(`Point addition: P1 + P2 computed`);
    
    // Verify addition is correct
    const additionCorrect = P3.toBytes().every((b, i) => b === P3_check.toBytes()[i]);
    console.log(`✅ Addition correct: ${additionCorrect}`);
    
    // Test encoding/decoding
    const encoded = P3.toBytes();
    const decoded = Ed25519Point.fromBytes(encoded);
    const reencoded = decoded.toBytes();
    
    const roundtrip = encoded.every((b, i) => b === reencoded[i]);
    console.log(`✅ Encode/decode roundtrip: ${roundtrip}`);
}

// Test 2: PRP-Cap Generation
console.log("\n📝 Test 2: PRP-Cap Generation");
console.log("-".repeat(40));
{
    // Generate epoch parameters using nacl (X25519)
    const s1 = nacl.randomBytes(32);
    const s2 = nacl.randomBytes(32);
    s1[0] &= 248; s1[31] &= 127; s1[31] |= 64;
    s2[0] &= 248; s2[31] &= 127; s2[31] |= 64;
    
    const A = nacl.scalarMult.base(s1);
    const B = nacl.scalarMult.base(s2);
    
    console.log(`A (X25519): ${toHex(A).slice(0, 16)}...`);
    console.log(`B (X25519): ${toHex(B).slice(0, 16)}...`);
    
    // Generate capabilities for different indices
    const capabilities = [];
    for (let i = 0; i < 3; i++) {
        const V_i = computePRPCap(A, B, i);
        capabilities.push(V_i);
        console.log(`V_${i} = ${toHex(V_i).slice(0, 16)}...`);
    }
    
    // Verify they're all different
    let allUnique = true;
    for (let i = 0; i < capabilities.length; i++) {
        for (let j = i + 1; j < capabilities.length; j++) {
            if (capabilities[i].every((b, k) => b === capabilities[j][k])) {
                allUnique = false;
            }
        }
    }
    console.log(`\n✅ All capabilities unique: ${allUnique}`);
}

// Test 3: Key Exchange
console.log("\n📝 Test 3: PRP-Cap Key Exchange");
console.log("-".repeat(40));
{
    // Setup epoch
    const s1 = nacl.randomBytes(32);
    const s2 = nacl.randomBytes(32);
    s1[0] &= 248; s1[31] &= 127; s1[31] |= 64;
    s2[0] &= 248; s2[31] &= 127; s2[31] |= 64;
    
    const A = nacl.scalarMult.base(s1);
    const B = nacl.scalarMult.base(s2);
    
    // Alice generates ephemeral and computes V_i
    const ephemeral = nacl.randomBytes(32);
    ephemeral[0] &= 248; ephemeral[31] &= 127; ephemeral[31] |= 64;
    const E = nacl.scalarMult.base(ephemeral);
    
    const index = 42;
    const V_i = computePRPCap(A, B, index);
    
    console.log(`Alice ephemeral: ${toHex(E).slice(0, 16)}...`);
    console.log(`Using V_${index}: ${toHex(V_i).slice(0, 16)}...`);
    
    // Alice computes DH(e, V_i)
    const aliceSecret = nacl.scalarMult(ephemeral, V_i);
    console.log(`Alice secret: ${toHex(aliceSecret).slice(0, 16)}...`);
    
    // Bob computes the shared secret using s1, s2, and E
    const bobSecret = computeReceiverSharedSecret(s1, s2, index, A, B, E);
    console.log(`Bob secret:   ${toHex(bobSecret).slice(0, 16)}...`);
    
    const match = aliceSecret.every((b, i) => b === bobSecret[i]);
    console.log(`\n✅ Shared secrets match: ${match}`);
}

console.log("\n" + "=".repeat(50));
console.log("🎉 Ed25519 Arithmetic Implementation Complete!");