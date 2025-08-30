import React, { useMemo } from 'react';
import { IconQrcode } from '@tabler/icons-react';
import { base32CrockfordToUint8Array, decodePRPCapPublicKey } from '../utils/encoding';

interface EncryptDecryptCardProps {
  recipientPublicKey: string;
  setRecipientPublicKey: (key: string) => void;
  message: string;
  setMessage: (msg: string) => void;
  isEncrypting: boolean;
  isDecrypting: boolean;
  onEncrypt: () => void;
  onDecrypt: () => void;
  hasCamera: boolean | null;
  onOpenScanner: () => void;
  useRatchet: boolean;
  onToggleRatchet: () => void;
  ratchetInitialized: boolean;
}

export const EncryptDecryptCard: React.FC<EncryptDecryptCardProps> = ({
  recipientPublicKey,
  setRecipientPublicKey,
  message,
  setMessage,
  isEncrypting,
  isDecrypting,
  onEncrypt,
  onDecrypt,
  hasCamera,
  onOpenScanner,
  useRatchet,
  onToggleRatchet,
  ratchetInitialized
}) => {
  // Validate and parse the recipient's public key
  const keyValidation = useMemo(() => {
    if (!recipientPublicKey || recipientPublicKey.trim() === '') {
      return { valid: false, message: '', details: null };
    }

    const trimmedKey = recipientPublicKey.trim();

    // Try to decode as Base32 Crockford
    try {
      const keyBytes = base32CrockfordToUint8Array(trimmedKey);
      
      // Check if it's a PRP-Cap encoded key
      if (keyBytes[0] === 0x01) {
        const decoded = decodePRPCapPublicKey(trimmedKey);
        if (decoded) {
          const epochDate = new Date(decoded.validUntil);
          const isExpired = epochDate < new Date();
          
          return {
            valid: !isExpired,
            message: isExpired ? 'PRP-Cap key (EXPIRED)' : 'Valid PRP-Cap key with epoch parameters',
            details: {
              type: 'PRP-Cap',
              length: keyBytes.length,
              format: 'Full PRP-Cap bundle',
              epochId: decoded.epochId.substring(0, 16) + '...',
              validUntil: epochDate.toLocaleDateString(),
              isExpired
            }
          };
        }
      }
      
      // Check standard key sizes
      if (keyBytes.length === 32) {
        return {
          valid: true,
          message: 'Valid identity key (32 bytes)',
          details: {
            type: 'Base32',
            length: keyBytes.length,
            format: 'X25519 identity key only'
          }
        };
      } else if (keyBytes.length === 96) {
        return {
          valid: true,
          message: 'Valid key bundle (96 bytes)',
          details: {
            type: 'Base32',
            length: keyBytes.length,
            format: 'Bundle (Identity + Epoch A + Epoch B)'
          }
        };
      } else {
        return {
          valid: false,
          message: `Invalid key length: ${keyBytes.length} bytes`,
          details: null
        };
      }
    } catch (error) {
      return {
        valid: false,
        message: 'Invalid Base32 encoding',
        details: null
      };
    }
  }, [recipientPublicKey]);
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
        justifyContent: 'space-between', 
        alignItems: 'center',
        marginBottom: '20px'
      }}>
        <h3 style={{ 
          margin: 0, 
          fontSize: '18px', 
          color: '#333' 
        }}>
          💬 Encrypt/Decrypt Messages
        </h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {ratchetInitialized && (
            <span style={{
              padding: '4px 8px',
              borderRadius: '12px',
              backgroundColor: '#4CAF50',
              color: 'white',
              fontSize: '11px',
              fontWeight: 'bold'
            }}>
              RATCHET ACTIVE
            </span>
          )}
          <button
            onClick={onToggleRatchet}
            style={{
              padding: '6px 12px',
              backgroundColor: useRatchet ? '#4CAF50' : '#f0f0f0',
              color: useRatchet ? 'white' : '#333',
              border: '1px solid ' + (useRatchet ? '#4CAF50' : '#ddd'),
              borderRadius: '6px',
              fontSize: '12px',
              cursor: 'pointer',
              transition: 'all 0.2s'
            }}
          >
            {useRatchet ? '🔐 Ratchet ON' : '🔓 Ratchet OFF'}
          </button>
        </div>
      </div>

      <div style={{ marginBottom: '20px' }}>
        <label style={{ 
          display: 'block', 
          marginBottom: '8px', 
          fontSize: '14px', 
          fontWeight: '500', 
          color: '#555' 
        }}>
          Recipient's Public Key: {useRatchet && !ratchetInitialized && recipientPublicKey && (
            <span style={{ color: '#ff9800', fontSize: '12px', marginLeft: '8px' }}>
              (Ratchet will initialize on first message)
            </span>
          )}
        </label>
        <div style={{ display: 'flex', gap: '8px' }}>
          <input
            type="text"
            value={recipientPublicKey}
            onChange={(e) => setRecipientPublicKey(e.target.value)}
            placeholder="Enter recipient's public key..."
            style={{
              flex: 1,
              padding: '10px',
              fontFamily: 'monospace',
              fontSize: '14px',
              border: '1px solid #e0e0e0',
              borderRadius: '6px',
              boxSizing: 'border-box'
            }}
          />
          {hasCamera && (
            <button 
              onClick={onOpenScanner} 
              title="Scan QR code"
              style={{
                padding: '10px',
                backgroundColor: 'white',
                border: '1px solid #e0e0e0',
                borderRadius: '6px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                transition: 'all 0.2s'
              }}
              onMouseOver={(e) => {
                e.currentTarget.style.backgroundColor = '#f5f5f5';
                e.currentTarget.style.borderColor = '#2196F3';
              }}
              onMouseOut={(e) => {
                e.currentTarget.style.backgroundColor = 'white';
                e.currentTarget.style.borderColor = '#e0e0e0';
              }}
            >
              <IconQrcode size={20} />
            </button>
          )}
        </div>
        
        {/* Key validation display */}
        {recipientPublicKey && keyValidation.message && (
          <div style={{
            marginTop: '8px',
            padding: '8px 12px',
            backgroundColor: keyValidation.valid ? '#e8f5e9' : '#ffebee',
            border: `1px solid ${keyValidation.valid ? '#4caf50' : '#f44336'}`,
            borderRadius: '4px',
            fontSize: '12px',
            color: keyValidation.valid ? '#2e7d32' : '#c62828'
          }}>
            <div style={{ fontWeight: 'bold', marginBottom: keyValidation.details ? '4px' : '0' }}>
              {keyValidation.valid ? '✓' : '✗'} {keyValidation.message}
            </div>
            {keyValidation.details && (
              <div style={{ marginTop: '4px', fontSize: '11px', opacity: 0.9 }}>
                • Format: {keyValidation.details.format}<br/>
                • Size: {keyValidation.details.length} bytes<br/>
                {keyValidation.details.epochId && (
                  <>• Epoch ID: {keyValidation.details.epochId}<br/></>
                )}
                {keyValidation.details.validUntil && (
                  <>• Valid Until: {keyValidation.details.validUntil}</>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      <div style={{ marginBottom: '20px' }}>
        <label style={{ 
          display: 'block', 
          marginBottom: '8px', 
          fontSize: '14px', 
          fontWeight: '500', 
          color: '#555' 
        }}>
          Message:
        </label>
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter your message..."
          rows={4}
          style={{
            width: '100%',
            padding: '10px',
            fontFamily: 'monospace',
            fontSize: '14px',
            border: '1px solid #e0e0e0',
            borderRadius: '6px',
            boxSizing: 'border-box',
            resize: 'vertical',
            transition: 'border-color 0.2s'
          }}
        />
      </div>

      <div style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
        <button 
          onClick={onEncrypt}
          disabled={isEncrypting || isDecrypting}
          style={{
            flex: 1,
            padding: '12px',
            backgroundColor: isEncrypting || isDecrypting ? '#ccc' : '#4CAF50',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            fontSize: '16px',
            fontWeight: '500',
            cursor: isEncrypting || isDecrypting ? 'not-allowed' : 'pointer',
            transition: 'background-color 0.2s'
          }}
        >
          {isEncrypting ? 'Encrypting...' : 'Encrypt'}
        </button>
        <button 
          onClick={onDecrypt}
          disabled={isEncrypting || isDecrypting}
          style={{
            flex: 1,
            padding: '12px',
            backgroundColor: isEncrypting || isDecrypting ? '#ccc' : '#2196F3',
            color: 'white',
            border: 'none',
            borderRadius: '6px',
            fontSize: '16px',
            fontWeight: '500',
            cursor: isEncrypting || isDecrypting ? 'not-allowed' : 'pointer',
            transition: 'background-color 0.2s'
          }}
        >
          {isDecrypting ? 'Decrypting...' : 'Decrypt'}
        </button>
      </div>
    </div>
  );
};
