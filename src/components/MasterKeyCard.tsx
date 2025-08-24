import React, { useState } from 'react';

interface MasterKeyCardProps {
  masterKey: string;
  onLock: () => void;
  onChangeMasterKey?: (newMasterKey: string) => Promise<boolean>;
  isLocking?: boolean;
  isChangingMasterKey?: boolean;
}

export const MasterKeyCard: React.FC<MasterKeyCardProps> = ({ 
  masterKey, 
  onLock, 
  onChangeMasterKey,
  isLocking = false,
  isChangingMasterKey = false
}) => {
  const [isEditing, setIsEditing] = useState(false);
  const [currentKeyVerify, setCurrentKeyVerify] = useState('');
  const [newMasterKey, setNewMasterKey] = useState('');
  const [confirmMasterKey, setConfirmMasterKey] = useState('');
  const [error, setError] = useState('');
  const handleLock = () => {
    if (window.confirm('Lock the app?\n\nThis will clear your master key from memory. Your encrypted private key remains in the URL.\n\nContinue?')) {
      onLock();
    }
  };

  const handleStartEdit = () => {
    setIsEditing(true);
    setError('');
    setCurrentKeyVerify('');
    setNewMasterKey('');
    setConfirmMasterKey('');
  };

  const handleCancelEdit = () => {
    setIsEditing(false);
    setError('');
    setCurrentKeyVerify('');
    setNewMasterKey('');
    setConfirmMasterKey('');
  };

  const handleSave = async () => {
    setError('');
    
    // Validate current key
    if (currentKeyVerify !== masterKey) {
      setError('Current master key is incorrect');
      return;
    }
    
    // Validate new key
    if (newMasterKey.length < 12) {
      setError('New master key must be at least 12 characters');
      return;
    }
    
    if (newMasterKey !== confirmMasterKey) {
      setError('New master keys do not match');
      return;
    }
    
    if (newMasterKey === masterKey) {
      setError('New master key must be different from current');
      return;
    }
    
    if (onChangeMasterKey) {
      const success = await onChangeMasterKey(newMasterKey);
      if (success) {
        handleCancelEdit();
      } else {
        setError('Failed to change master key');
      }
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
        <div style={{ display: 'flex', gap: '8px' }}>
          {!isEditing && onChangeMasterKey && (
            <button
              onClick={handleStartEdit}
              disabled={isChangingMasterKey}
              title="Change master key"
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
              onMouseOver={(e) => (e.currentTarget.style.borderColor = '#2196F3')}
              onMouseOut={(e) => (e.currentTarget.style.borderColor = '#e0e0e0')}
            >
              ✏️ Change
            </button>
          )}
          <button
            onClick={handleLock}
            disabled={isLocking || isEditing}
            title="Lock the app"
            style={{
              background: isLocking ? '#FFA500' : 'white',
              border: '1px solid #e0e0e0',
              borderRadius: '6px',
              padding: '4px 10px',
              cursor: isLocking || isEditing ? 'not-allowed' : 'pointer',
              fontSize: '13px',
              color: isLocking ? 'white' : '#666',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              transition: 'all 0.2s',
              opacity: isEditing ? 0.5 : 1
            }}
            onMouseOver={(e) => !isLocking && !isEditing && (e.currentTarget.style.borderColor = '#f44336')}
            onMouseOut={(e) => !isLocking && !isEditing && (e.currentTarget.style.borderColor = '#e0e0e0')}
          >
            🔒 {isLocking ? 'Locking...' : 'Lock'}
          </button>
        </div>
      </div>
      
      {isEditing ? (
        <div>
          {error && (
            <div style={{
              padding: '8px',
              marginBottom: '10px',
              backgroundColor: '#ffebee',
              color: '#c62828',
              borderRadius: '4px',
              fontSize: '13px'
            }}>
              {error}
            </div>
          )}
          
          <div style={{ marginBottom: '12px' }}>
            <label style={{
              display: 'block',
              marginBottom: '4px',
              fontSize: '13px',
              color: '#666'
            }}>
              Current Master Key:
            </label>
            <input
              type="password"
              value={currentKeyVerify}
              onChange={(e) => setCurrentKeyVerify(e.target.value)}
              placeholder="Enter current master key"
              style={{
                width: '100%',
                padding: '8px',
                fontFamily: 'monospace',
                fontSize: '14px',
                border: '1px solid #e0e0e0',
                borderRadius: '4px',
                boxSizing: 'border-box'
              }}
            />
          </div>
          
          <div style={{ marginBottom: '12px' }}>
            <label style={{
              display: 'block',
              marginBottom: '4px',
              fontSize: '13px',
              color: '#666'
            }}>
              New Master Key:
            </label>
            <input
              type="password"
              value={newMasterKey}
              onChange={(e) => setNewMasterKey(e.target.value)}
              placeholder="Enter new master key (min 12 characters)"
              style={{
                width: '100%',
                padding: '8px',
                fontFamily: 'monospace',
                fontSize: '14px',
                border: '1px solid #e0e0e0',
                borderRadius: '4px',
                boxSizing: 'border-box'
              }}
            />
          </div>
          
          <div style={{ marginBottom: '12px' }}>
            <label style={{
              display: 'block',
              marginBottom: '4px',
              fontSize: '13px',
              color: '#666'
            }}>
              Confirm New Master Key:
            </label>
            <input
              type="password"
              value={confirmMasterKey}
              onChange={(e) => setConfirmMasterKey(e.target.value)}
              placeholder="Confirm new master key"
              style={{
                width: '100%',
                padding: '8px',
                fontFamily: 'monospace',
                fontSize: '14px',
                border: '1px solid #e0e0e0',
                borderRadius: '4px',
                boxSizing: 'border-box'
              }}
            />
          </div>
          
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={handleSave}
              disabled={isChangingMasterKey}
              style={{
                flex: 1,
                padding: '8px',
                backgroundColor: isChangingMasterKey ? '#ccc' : '#4CAF50',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: isChangingMasterKey ? 'not-allowed' : 'pointer',
                fontSize: '14px',
                fontWeight: '500'
              }}
            >
              {isChangingMasterKey ? 'Changing...' : 'Save'}
            </button>
            <button
              onClick={handleCancelEdit}
              disabled={isChangingMasterKey}
              style={{
                flex: 1,
                padding: '8px',
                backgroundColor: 'white',
                color: '#666',
                border: '1px solid #e0e0e0',
                borderRadius: '4px',
                cursor: isChangingMasterKey ? 'not-allowed' : 'pointer',
                fontSize: '14px'
              }}
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
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
      )}
    </div>
  );
};