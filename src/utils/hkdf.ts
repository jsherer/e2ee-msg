/**
 * HKDF (HMAC-based Key Derivation Function) implementation using Web Crypto API
 * RFC 5869: https://tools.ietf.org/html/rfc5869
 */

/**
 * HKDF-Extract: Extract a pseudorandom key from input keying material
 * @param salt - Salt value (can be empty)
 * @param ikm - Input keying material
 * @returns Pseudorandom key (PRK)
 */
export async function hkdfExtract(
  salt: Uint8Array,
  ikm: Uint8Array
): Promise<Uint8Array> {
  // Ensure we have proper Uint8Arrays
  const saltToUse = salt.length === 0 ? new Uint8Array(32) : new Uint8Array(salt);
  const ikmToUse = new Uint8Array(ikm);
  
  // Import salt as HMAC key
  const saltKey = await crypto.subtle.importKey(
    'raw',
    saltToUse,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  // PRK = HMAC-Hash(salt, IKM)
  const prk = await crypto.subtle.sign('HMAC', saltKey, ikmToUse);
  return new Uint8Array(prk);
}

/**
 * HKDF-Expand: Expand a pseudorandom key to desired length
 * @param prk - Pseudorandom key from Extract step
 * @param info - Context/application specific information
 * @param length - Desired output length in bytes
 * @returns Output keying material (OKM)
 */
export async function hkdfExpand(
  prk: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  if (length > 255 * 32) {
    throw new Error('Output length exceeds maximum (255 * HashLen)');
  }

  // Ensure we have proper Uint8Array
  const prkToUse = new Uint8Array(prk);
  
  // Import PRK as HMAC key
  const prkKey = await crypto.subtle.importKey(
    'raw',
    prkToUse,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const okm = new Uint8Array(length);
  let offset = 0;
  let counter = 1;
  let previousBlock = new Uint8Array(0);

  while (offset < length) {
    // T(i) = HMAC(PRK, T(i-1) || info || counter)
    const input = new Uint8Array(previousBlock.length + info.length + 1);
    input.set(previousBlock, 0);
    input.set(info, previousBlock.length);
    input[previousBlock.length + info.length] = counter;

    const block = new Uint8Array(
      await crypto.subtle.sign('HMAC', prkKey, input)
    );

    const bytesToCopy = Math.min(32, length - offset);
    okm.set(block.slice(0, bytesToCopy), offset);

    previousBlock = block;
    offset += bytesToCopy;
    counter++;
  }

  return okm;
}

/**
 * Combined HKDF function (Extract + Expand)
 * @param salt - Salt value
 * @param ikm - Input keying material
 * @param info - Context information
 * @param length - Desired output length
 * @returns Output keying material
 */
export async function hkdf(
  salt: Uint8Array,
  ikm: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  const prk = await hkdfExtract(salt, ikm);
  return hkdfExpand(prk, info, length);
}