/**
 * Hook for managing Double Ratchet Protocol state and operations
 */

import { useState, useCallback, useRef } from 'react';
import { RatchetState, RatchetOperation } from '../types/ratchet';
import { KeyPair } from '../types';
import {
  initializeRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
  getRatchetStorageKey
} from '../utils/ratchet';

const MAX_OPERATIONS = 20; // Maximum operations to keep in history

export const useRatchet = (
  keypair: KeyPair | null
) => {
  const [ratchetSessions, setRatchetSessions] = useState<Map<string, RatchetState>>(new Map());
  const [currentSessionKey, setCurrentSessionKey] = useState<string | null>(null);
  const [operations, setOperations] = useState<RatchetOperation[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const operationIdRef = useRef(0);

  // Add operation to history
  const addOperation = useCallback((type: RatchetOperation['type'], details: string) => {
    const operation: RatchetOperation = {
      timestamp: Date.now(),
      type,
      details
    };
    
    setOperations(prev => {
      const newOps = [operation, ...prev];
      return newOps.slice(0, MAX_OPERATIONS);
    });
  }, []);

  // Sessions are now only kept in memory - no localStorage persistence

  // Initialize a new ratchet session
  const initializeSession = useCallback((theirPublicKey: Uint8Array): RatchetState | null => {
    if (!keypair) {
      addOperation('error', 'No keypair available');
      return null;
    }

    setIsProcessing(true);
    
    try {
      const state = initializeRatchet(keypair, theirPublicKey);
      const sessionKey = getRatchetStorageKey(keypair.publicKey, theirPublicKey);
      
      setRatchetSessions(prev => {
        const newSessions = new Map(prev);
        newSessions.set(sessionKey, state);
        return newSessions;
      });
      
      setCurrentSessionKey(sessionKey);
      
      addOperation('init', `Session initialized with ${Array.from(theirPublicKey.slice(0, 4)).map(b => b.toString(16).padStart(2, '0')).join('')}...`);
      
      return state;
    } catch (error) {
      console.error('Failed to initialize ratchet:', error);
      addOperation('error', `Initialization failed: ${error}`);
      return null;
    } finally {
      setIsProcessing(false);
    }
  }, [keypair, addOperation]);

  // Get or create session for a recipient
  const getOrCreateSession = useCallback((theirPublicKey: Uint8Array): RatchetState | null => {
    if (!keypair) return null;
    
    const sessionKey = getRatchetStorageKey(keypair.publicKey, theirPublicKey);
    const existingSession = ratchetSessions.get(sessionKey);
    
    if (existingSession) {
      setCurrentSessionKey(sessionKey);
      return existingSession;
    }
    
    return initializeSession(theirPublicKey);
  }, [keypair, ratchetSessions, initializeSession]);

  // Encrypt a message with ratchet
  const encryptWithRatchet = useCallback((
    message: string,
    theirPublicKey: Uint8Array
  ): Uint8Array | null => {
    if (!keypair) {
      addOperation('error', 'No keypair available');
      return null;
    }

    setIsProcessing(true);
    
    try {
      let state = getOrCreateSession(theirPublicKey);
      if (!state) {
        addOperation('error', 'Failed to get or create session');
        return null;
      }
      
      const plaintext = new TextEncoder().encode(message);
      const [encrypted, newState] = ratchetEncrypt(state, plaintext);
      
      // Update session
      const sessionKey = getRatchetStorageKey(keypair.publicKey, theirPublicKey);
      setRatchetSessions(prev => {
        const newSessions = new Map(prev);
        newSessions.set(sessionKey, newState);
        return newSessions;
      });
      
      
      // Add operation
      const dhRatcheted = state.theirLatestEphemeralPublicKey !== null;
      if (dhRatcheted && newState.sendMessageCounter === 1) {
        addOperation('dh-ratchet', 'DH ratchet performed');
      }
      addOperation('encrypt', `Message #${newState.sendMessageCounter} encrypted`);
      
      return encrypted;
    } catch (error) {
      console.error('Encryption failed:', error);
      addOperation('error', `Encryption failed: ${error}`);
      return null;
    } finally {
      setIsProcessing(false);
    }
  }, [keypair, getOrCreateSession, addOperation]);

  // Decrypt a message with ratchet
  const decryptWithRatchet = useCallback((
    encrypted: Uint8Array,
    theirPublicKey: Uint8Array
  ): string | null => {
    if (!keypair) {
      addOperation('error', 'No keypair available');
      return null;
    }

    setIsProcessing(true);
    
    try {
      let state = getOrCreateSession(theirPublicKey);
      if (!state) {
        addOperation('error', 'Failed to get or create session');
        return null;
      }
      
      const oldEphemeral = state.theirLatestEphemeralPublicKey;
      const oldCounter = state.receiveMessageCounter;
      
      const [plaintext, newState] = ratchetDecrypt(state, encrypted);
      
      // Update session
      const sessionKey = getRatchetStorageKey(keypair.publicKey, theirPublicKey);
      setRatchetSessions(prev => {
        const newSessions = new Map(prev);
        newSessions.set(sessionKey, newState);
        return newSessions;
      });
      
      
      // Add operations
      const dhRatcheted = !oldEphemeral || 
        !newState.theirLatestEphemeralPublicKey ||
        !constantTimeEqual(oldEphemeral, newState.theirLatestEphemeralPublicKey);
      
      if (dhRatcheted) {
        addOperation('dh-ratchet', 'DH ratchet performed');
      }
      
      if (newState.receiveMessageCounter > oldCounter + 1) {
        addOperation('skip-messages', `Skipped messages ${oldCounter}-${newState.receiveMessageCounter - 1}`);
      }
      
      addOperation('decrypt', `Message #${newState.receiveMessageCounter} decrypted`);
      
      return new TextDecoder().decode(plaintext);
    } catch (error) {
      console.error('Decryption failed:', error);
      addOperation('error', `Decryption failed: ${error}`);
      return null;
    } finally {
      setIsProcessing(false);
    }
  }, [keypair, getOrCreateSession, addOperation]);

  // Reset a session
  const resetSession = useCallback((theirPublicKey: Uint8Array) => {
    if (!keypair) return;
    
    const sessionKey = getRatchetStorageKey(keypair.publicKey, theirPublicKey);
    
    // Remove from state
    setRatchetSessions(prev => {
      const newSessions = new Map(prev);
      newSessions.delete(sessionKey);
      return newSessions;
    });
    
    // Clear current session if it matches
    if (currentSessionKey === sessionKey) {
      setCurrentSessionKey(null);
    }
    
    addOperation('init', 'Session reset');
  }, [keypair, currentSessionKey, addOperation]);

  // Get current session state
  const getCurrentSession = useCallback((): RatchetState | null => {
    if (!currentSessionKey) return null;
    return ratchetSessions.get(currentSessionKey) || null;
  }, [currentSessionKey, ratchetSessions]);

  // Clear all sessions
  const clearAllSessions = useCallback(() => {
    // Clear state
    setRatchetSessions(new Map());
    setCurrentSessionKey(null);
    setOperations([]);
    
    addOperation('init', 'All sessions cleared');
  }, [addOperation]);

  return {
    // Session management
    initializeSession,
    getOrCreateSession,
    resetSession,
    clearAllSessions,
    
    // Encryption/Decryption
    encryptWithRatchet,
    decryptWithRatchet,
    
    // State access
    getCurrentSession,
    currentSessionKey,
    sessionCount: ratchetSessions.size,
    
    // UI state
    operations,
    isProcessing
  };
};

// Helper function for constant-time comparison
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}