/**
 * Hook for managing cryptographic keys and master key with secure URL storage
 */

import { useState, useEffect, useMemo, useCallback } from 'react';
import { KeyPair, KeyPairDisplay } from '../types';
import {
  generateKeyPair,
  generateKeyPairFromSecretKey,
  encryptSecretKey,
  decryptSecretKey
} from '../utils/crypto';
import type { ExtendedKeyPair } from '../types/keys';
import {
  uint8ArrayToBase32Crockford,
  base32CrockfordToUint8Array,
  formatInGroups,
  generateUserId
} from '../utils/encoding';
import { encryptToFragment, decryptFromFragment, PlainPayload } from '../utils/seal';

interface KeyData {
  secretKey: string; // Base32 encoded secret key
  publicKey: string; // Base32 encoded public key
  ephemeralSeedSecret?: string; // Base32 encoded ephemeral seed secret (Ladder)
  ephemeralSeedPublic?: string; // Base32 encoded ephemeral seed public (Ladder)
  timestamp: number;
}

export const useKeyManagement = () => {
  const [keypair, setKeypair] = useState<KeyPair | null>(null);
  const [keypairDisplay, setKeypairDisplay] = useState<KeyPairDisplay | null>(null);
  const [ephemeralSeed, setEphemeralSeed] = useState<KeyPair | null>(null);
  const [masterKey, setMasterKey] = useState('');
  const [masterKeyLocked, setMasterKeyLocked] = useState(false);
  const [waitingForMasterKey, setWaitingForMasterKey] = useState(false);
  const [nonceCounter, setNonceCounter] = useState(0);
  const [lastSeenSeq, setLastSeenSeq] = useState(0);
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [isSavingKeys, setIsSavingKeys] = useState(false);
  const [isLocking, setIsLocking] = useState(false);

  const saveKeysToUrl = useCallback(async (pair: KeyPair, seed: KeyPair | null, passphrase: string) => {
    setIsSavingKeys(true);
    try {
      const keyData: KeyData = {
        secretKey: uint8ArrayToBase32Crockford(pair.secretKey),
        publicKey: uint8ArrayToBase32Crockford(pair.publicKey),
        ephemeralSeedSecret: seed ? uint8ArrayToBase32Crockford(seed.secretKey) : undefined,
        ephemeralSeedPublic: seed ? uint8ArrayToBase32Crockford(seed.publicKey) : undefined,
        timestamp: Date.now()
      };

      // Get existing params if we have a fragment
      let existingParams = undefined;
      let seq = 1;
      
      const currentHash = window.location.hash.slice(1);
      if (currentHash && currentHash.startsWith('v1.scrypt')) {
        try {
          const { params, payload } = await decryptFromFragment<KeyData>(passphrase, currentHash);
          existingParams = params;
          seq = (payload.seq || 0) + 1;
        } catch {
          // If decryption fails, start fresh
        }
      }

      const fragment = await encryptToFragment(passphrase, keyData, {
        N: 16384, // Lower for mobile/browser performance
        r: 8,
        p: 1,
        salt: existingParams?.salt, // Reuse salt if we have one
        seq,
        context: location.origin
      });

      // Replace the URL without adding to history
      history.replaceState(null, '', location.pathname + location.search + '#' + fragment);
      setLastSeenSeq(seq);
    } catch (error) {
      console.error('Failed to save keys to URL:', error);
    } finally {
      setIsSavingKeys(false);
    }
  }, []);

  const generateNewKeypair = useCallback(async () => {
    const pair = generateKeyPair();
    const seed = generateKeyPair(); // Generate ephemeral seed for Ladder
    
    setKeypair(pair);
    setEphemeralSeed(seed);
    
    const publicKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.publicKey));
    const secretKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.secretKey));
    
    setKeypairDisplay({
      publicKey: publicKeyBase32,
      secretKey: secretKeyBase32
    });
    
    // Save to URL if we have a master key (regeneration case)
    if (masterKey && masterKeyLocked) {
      await saveKeysToUrl(pair, seed, masterKey);
    }
    
    return pair;
  }, [masterKey, masterKeyLocked, saveKeysToUrl]);

  const tryRestoreFromFragment = useCallback(async (passphrase: string): Promise<boolean> => {
    try {
      const hash = window.location.hash.slice(1);
      if (!hash || !hash.startsWith('v1.scrypt')) {
        return false;
      }

      const { payload, rotate } = await decryptFromFragment<KeyData>(passphrase, hash, {
        lastSeenSeq
      });

      // Restore the keypair
      const secretKeyBytes = base32CrockfordToUint8Array(payload.data.secretKey);
      const pair = generateKeyPairFromSecretKey(secretKeyBytes);
      
      setKeypair(pair);
      
      // Restore ephemeral seed if present (Ladder protocol)
      if (payload.data.ephemeralSeedSecret) {
        const seedSecretBytes = base32CrockfordToUint8Array(payload.data.ephemeralSeedSecret);
        const seed = generateKeyPairFromSecretKey(seedSecretBytes);
        setEphemeralSeed(seed);
      }
      
      const publicKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.publicKey));
      const secretKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.secretKey));
      
      setKeypairDisplay({
        publicKey: publicKeyBase32,
        secretKey: secretKeyBase32
      });

      setLastSeenSeq(payload.seq);

      // Rotate the fragment with a fresh nonce
      const rotated = await rotate(true);
      history.replaceState(null, '', location.pathname + location.search + '#' + rotated);
      
      return true;
    } catch (error) {
      console.error('Failed to restore from fragment:', error);
      return false;
    }
  }, [lastSeenSeq]);

  const handleMasterKeySubmit = useCallback(async () => {
    if (!masterKey || masterKey.length < 12) {
      return false;
    }
    
    setIsUnlocking(true);
    const hash = window.location.hash.slice(1);
    
    // Check for new seal format
    if (hash && hash.startsWith('v1.scrypt')) {
      // Try to decrypt existing sealed data
      const restored = await tryRestoreFromFragment(masterKey);
      if (restored) {
        setWaitingForMasterKey(false);
        setMasterKeyLocked(true);
        setIsUnlocking(false);
        return true;
      } else {
        alert('Invalid master key for the encrypted data in URL');
        setIsUnlocking(false);
        return false;
      }
    } 
    // Check for old format (backwards compatibility)
    else if (hash) {
      try {
        const encryptedData = base32CrockfordToUint8Array(hash);
        const decrypted = decryptSecretKey(encryptedData, masterKey);
        
        if (decrypted && decrypted.length === 32) {
          const pair = generateKeyPairFromSecretKey(decrypted);
          
          setKeypair(pair);
          
          const publicKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.publicKey));
          const secretKeyBase32 = formatInGroups(uint8ArrayToBase32Crockford(pair.secretKey));
          
          setKeypairDisplay({
            publicKey: publicKeyBase32,
            secretKey: secretKeyBase32
          });
          
          // Migrate to new format (generate ephemeral seed for Ladder)
          const seed = generateKeyPair();
          setEphemeralSeed(seed);
          await saveKeysToUrl(pair, seed, masterKey);
          setWaitingForMasterKey(false);
          setMasterKeyLocked(true);
          setIsUnlocking(false);
          return true;
        }
      } catch (error) {
        console.error('Failed to restore from old format:', error);
        alert('Invalid master key for the encrypted private key in URL');
        setIsUnlocking(false);
        return false;
      }
    }
    // No existing hash, generate new
    else {
      const pair = await generateNewKeypair();
      await saveKeysToUrl(pair, ephemeralSeed, masterKey);
      setMasterKeyLocked(true);
      setIsUnlocking(false);
      return true;
    }
    
    setIsUnlocking(false);
    return false;
  }, [masterKey, tryRestoreFromFragment, saveKeysToUrl]);

  const lockApp = useCallback(async () => {
    setIsLocking(true);
    try {
      // Rotate the fragment with a fresh nonce before locking
      if (keypair && masterKey && window.location.hash) {
        const hash = window.location.hash.slice(1);
        if (hash && hash.startsWith('v1.scrypt')) {
          try {
            const { rotate } = await decryptFromFragment<KeyData>(masterKey, hash, {
              lastSeenSeq  
            });
            // Just rotate with fresh nonce, don't bump sequence when locking
            const rotated = await rotate(false);
            history.replaceState(null, '', location.pathname + location.search + '#' + rotated);
            // Wait a moment to ensure the URL is updated
            await new Promise(resolve => setTimeout(resolve, 50));
          } catch (error) {
            console.error('Failed to rotate fragment before locking:', error);
          }
        }
      }
      
      // Only clear the master key and show locked screen AFTER fragment is rotated
      setMasterKey('');
      setMasterKeyLocked(false);
      // Reset lastSeenSeq when locking so next unlock doesn't fail anti-rollback
      setLastSeenSeq(0);
      if (window.location.hash) {
        setWaitingForMasterKey(true);
      }
    } finally {
      setIsLocking(false);
    }
  }, [keypair, masterKey, lastSeenSeq]);

  const encryptedPrivateKey = useMemo(() => {
    // This is now handled by the seal in the URL
    // Return a placeholder or the fragment itself for display
    const hash = window.location.hash.slice(1);
    if (hash && hash.startsWith('v1.scrypt')) {
      // Just show a truncated version for UI display
      return hash.slice(0, 20) + '...';
    }
    return null;
  }, [nonceCounter]); // Still respond to nonce updates

  const userId = useMemo(() => {
    if (!keypair) return null;
    return generateUserId(keypair.publicKey);
  }, [keypair]);

  // Check for encrypted key in URL on mount
  useEffect(() => {
    const hash = window.location.hash.slice(1);
    if (hash && hash.startsWith('v1.scrypt')) {
      setWaitingForMasterKey(true);
    }
  }, []);

  // Note: We don't need to constantly update the URL fragment.
  // It's only updated when:
  // 1. Keys are initially generated (in handleMasterKeySubmit)
  // 2. Keys are regenerated (in generateNewKeypair, called explicitly)
  // 3. On lock (for nonce rotation)
  // 4. On unlock (for nonce rotation)

  const incrementNonceCounter = () => {
    setNonceCounter(prev => prev + 1);
  };

  // Format 64-byte bundle for Ladder protocol (IK_dh_pub || ES_pub)
  const formatPublicKeyBundle = useCallback((): Uint8Array | null => {
    if (!keypair || !ephemeralSeed) return null;
    const bundle = new Uint8Array(64);
    bundle.set(keypair.publicKey, 0);
    bundle.set(ephemeralSeed.publicKey, 32);
    return bundle;
  }, [keypair, ephemeralSeed]);

  const changeMasterKey = useCallback(async (newMasterKey: string): Promise<boolean> => {
    if (!keypair || !masterKey || newMasterKey.length < 12) {
      return false;
    }

    try {
      // Save keys with new master key
      await saveKeysToUrl(keypair, ephemeralSeed, newMasterKey);
      
      // Update the master key in state
      setMasterKey(newMasterKey);
      
      return true;
    } catch (error) {
      console.error('Failed to change master key:', error);
      return false;
    }
  }, [keypair, masterKey, saveKeysToUrl]);

  return {
    keypair,
    keypairDisplay,
    ephemeralSeed,
    masterKey,
    setMasterKey,
    masterKeyLocked,
    waitingForMasterKey,
    encryptedPrivateKey,
    userId,
    generateNewKeypair,
    handleMasterKeySubmit,
    lockApp,
    incrementNonceCounter,
    setWaitingForMasterKey,
    isUnlocking,
    isSavingKeys,
    isLocking,
    changeMasterKey,
    formatPublicKeyBundle,
  };
};
