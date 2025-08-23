import React, { useState } from 'react';
import { IconLock, IconLockPassword, IconLockOpen2 } from '@tabler/icons-react';

interface LockScreenProps {
  masterKey: string;
  setMasterKey: (key: string) => void;
  onUnlock: () => Promise<boolean>;
  waitingForMasterKey: boolean;
  onFreshStart: () => void;
  isUnlocking: boolean;
}

export const LockScreen: React.FC<LockScreenProps> = ({
  masterKey,
  setMasterKey,
  onUnlock,
  waitingForMasterKey,
  onFreshStart,
  isUnlocking
}) => {
  const [isUnlocked, setIsUnlocked] = useState(false);

  const handleSubmit = async () => {
    if (masterKey.length < 12) {
      alert('Master key must be at least 12 characters long');
      return;
    }
    const success = await onUnlock();
    if (success) {
      setIsUnlocked(true);
      // Brief delay to show the unlocked state
      setTimeout(() => {
        // Navigation will happen automatically via state change
      }, 500);
    }
  };

  const handleFreshStart = () => {
    if (window.confirm('This will clear the encrypted private key from the URL.\n\nYou will get a new keypair and lose access to messages encrypted with the old key.\n\nContinue?')) {
      onFreshStart();
    }
  };

  return (
    <div style={{ 
      height: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: 'Arial, sans-serif',
      backgroundColor: '#f5f5f5'
    }}>
      <div style={{
        backgroundColor: 'white',
        padding: '40px',
        borderRadius: '12px',
        boxShadow: '0 4px 6px rgba(0, 0, 0, 0.1)',
        maxWidth: '400px',
        width: '100%'
      }}>
        <div style={{ 
          margin: '0 0 10px 0',
          textAlign: 'center'
        }}>
          <div style={{ 
            display: 'flex', 
            justifyContent: 'center', 
            marginBottom: '10px' 
          }}>
            {isUnlocked ? (
              <IconLockOpen2 size={48} color="#4CAF50" />
            ) : isUnlocking ? (
              <IconLockPassword size={48} color="#FFA500" />
            ) : (
              <IconLock size={48} color="#666" />
            )}
          </div>
          <h1 style={{ 
            margin: 0,
            fontSize: '28px'
          }}>
            E2EE Local Messenger
          </h1>
        </div>
        
        <p style={{ 
          textAlign: 'center',
          color: '#666',
          marginBottom: '30px',
          fontSize: '14px'
        }}>
          Enter your master key to unlock
        </p>

        <input
          type="password"
          value={masterKey}
          onChange={(e) => setMasterKey(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && !isUnlocking && !isUnlocked && handleSubmit()}
          placeholder="Master key / password"
          autoFocus
          disabled={isUnlocking || isUnlocked}
          style={{
            width: '100%',
            padding: '12px',
            fontFamily: 'monospace',
            fontSize: '16px',
            border: '2px solid #ddd',
            borderRadius: '6px',
            marginBottom: '15px',
            boxSizing: 'border-box',
            opacity: isUnlocking || isUnlocked ? 0.6 : 1
          }}
        />
        
        <button
          onClick={handleSubmit}
          disabled={!masterKey || masterKey.length < 12 || isUnlocking || isUnlocked}
          style={{
            width: '100%',
            padding: '12px',
            backgroundColor: isUnlocked ? '#4CAF50' : isUnlocking ? '#FFA500' : (masterKey && masterKey.length >= 12 ? '#4CAF50' : '#ccc'),
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            fontSize: '16px',
            fontWeight: 'bold',
            cursor: isUnlocked || isUnlocking ? 'wait' : (masterKey && masterKey.length >= 12 ? 'pointer' : 'not-allowed'),
            transition: 'background-color 0.2s'
          }}
        >
          {isUnlocked ? 'Unlocked!' : isUnlocking ? 'Unlocking...' : 'Unlock'}
        </button>

        {waitingForMasterKey && (
          <>
            <p style={{ 
              fontSize: '12px', 
              color: '#ff9800',
              margin: '15px 0 0 0',
              textAlign: 'center'
            }}>
              📋 Encrypted key found in URL. Enter your master key to restore.
            </p>
            <button
              onClick={handleFreshStart}
              style={{
                background: 'transparent',
                color: '#666',
                border: 'none',
                fontSize: '11px',
                cursor: 'pointer',
                marginTop: '8px',
                textDecoration: 'underline',
                padding: '4px',
                transition: 'color 0.2s',
                display: 'block',
                margin: '8px auto 0',
                textAlign: 'center'
              }}
              onMouseOver={(e) => e.currentTarget.style.color = '#f44336'}
              onMouseOut={(e) => e.currentTarget.style.color = '#666'}
            >
              (Need a fresh start?)
            </button>
          </>
        )}
        
        {!waitingForMasterKey && (
          <p style={{ 
            fontSize: '12px', 
            color: '#666',
            margin: '15px 0 0 0',
            textAlign: 'center'
          }}>
            {masterKey.length > 0 && masterKey.length < 12 ? (
              <span style={{ color: '#ff9800' }}>
                {masterKey.length}/12 characters minimum
              </span>
            ) : masterKey.length >= 12 ? (
              'This key will encrypt your private keys for security'
            ) : (
              'This key will encrypt your private keys for security'
            )}
          </p>
        )}
      </div>
    </div>
  );
};