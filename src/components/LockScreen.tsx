import React from 'react';

interface LockScreenProps {
  masterKey: string;
  setMasterKey: (key: string) => void;
  onUnlock: () => void;
  waitingForMasterKey: boolean;
  onFreshStart: () => void;
}

export const LockScreen: React.FC<LockScreenProps> = ({
  masterKey,
  setMasterKey,
  onUnlock,
  waitingForMasterKey,
  onFreshStart
}) => {
  const handleSubmit = () => {
    if (masterKey.length < 12) {
      alert('Master key must be at least 12 characters long');
      return;
    }
    onUnlock();
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
        <h1 style={{ 
          margin: '0 0 10px 0',
          fontSize: '28px',
          textAlign: 'center'
        }}>
          🔐 E2EE Local Messenger
        </h1>
        
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
          onKeyPress={(e) => e.key === 'Enter' && handleSubmit()}
          placeholder="Master key / password"
          autoFocus
          style={{
            width: '100%',
            padding: '12px',
            fontFamily: 'monospace',
            fontSize: '16px',
            border: '2px solid #ddd',
            borderRadius: '6px',
            marginBottom: '15px',
            boxSizing: 'border-box'
          }}
        />
        
        <button
          onClick={handleSubmit}
          disabled={!masterKey || masterKey.length < 12}
          style={{
            width: '100%',
            padding: '12px',
            backgroundColor: masterKey && masterKey.length >= 12 ? '#4CAF50' : '#ccc',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            fontSize: '16px',
            fontWeight: 'bold',
            cursor: masterKey && masterKey.length >= 12 ? 'pointer' : 'not-allowed',
            transition: 'background-color 0.2s'
          }}
        >
          Unlock
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