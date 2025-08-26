/**
 * SHA-256 hash function using Web Crypto API
 */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // Ensure we have a proper Uint8Array
  const dataToHash = new Uint8Array(data);
  const hash = await crypto.subtle.digest('SHA-256', dataToHash);
  return new Uint8Array(hash);
}

/**
 * Clamp a scalar for X25519 operations
 */
export function clamp25519(scalar: Uint8Array): Uint8Array {
  const clamped = new Uint8Array(scalar);
  clamped[0] &= 248;
  clamped[31] &= 127;
  clamped[31] |= 64;
  return clamped;
}
