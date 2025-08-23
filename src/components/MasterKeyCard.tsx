import React from 'react';

interface MasterKeyCardProps {
  masterKey: string;
  onLock: () => void;
}

export const MasterKeyCard: React.FC<MasterKeyCardProps> = ({ masterKey, onLock }) => {
  const handleLock = () => {
    if (window.confirm('Lock the app?\n\nThis will clear your master key from memory. Your encrypted private key remains in the URL.\n\nContinue?')) {
      onLock();
    }
  };

  return (
    <div style={{
      backgroundColor: 'white',
      borderRadius: '8px',
      padding: '20px',
      marginBottom: '20px',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '10px'
      }}>
        <h3 style={{ 
          margin: 0,
          fontSize: '18px',
          color: '#333',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <span style={{ color: '#4CAF50' }}>✓</span>
          Master Key (Unlocked)
        </h3>
        <button
          onClick={handleLock}
          title="Lock the app"
          style={{
            background: 'white',
            border: '1px solid #e0e0e0',
            borderRadius: '6px',
            padding: '4px 10px',
            cursor: 'pointer',
            fontSize: '13px',
            color: '#666',
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
            transition: 'all 0.2s'
          }}
          onMouseOver={(e) => e.currentTarget.style.borderColor = '#f44336'}
          onMouseOut={(e) => e.currentTarget.style.borderColor = '#e0e0e0'}
        >
          🔒 Lock
        </button>
      </div>
      <div style={{
        padding: '10px',
        fontFamily: 'monospace',
        fontSize: '14px',
        border: '1px solid #e0e0e0',
        borderRadius: '6px',
        backgroundColor: '#fafafa'
      }}>
        {'•'.repeat(masterKey.length)}
      </div>
    </div>
  );
};