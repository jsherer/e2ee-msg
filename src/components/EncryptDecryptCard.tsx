import React from 'react';
import { IconQrcode, IconCopy, IconCheck } from '@tabler/icons-react';

interface EncryptDecryptCardProps {
  recipientPublicKey: string;
  setRecipientPublicKey: (key: string) => void;
  message: string;
  setMessage: (msg: string) => void;
  output: string;
  isEncrypting: boolean;
  isDecrypting: boolean;
  onEncrypt: () => void;
  onDecrypt: () => void;
  hasCamera: boolean | null;
  onOpenScanner: () => void;
  copiedOutput: boolean;
  onCopyOutput: () => void;
  useRatchet: boolean;
  onToggleRatchet: () => void;
  ratchetInitialized: boolean;
}

export const EncryptDecryptCard: React.FC<EncryptDecryptCardProps> = ({
  recipientPublicKey,
  setRecipientPublicKey,
  message,
  setMessage,
  output,
  isEncrypting,
  isDecrypting,
  onEncrypt,
  onDecrypt,
  hasCamera,
  onOpenScanner,
  copiedOutput,
  onCopyOutput,
  useRatchet,
  onToggleRatchet,
  ratchetInitialized
}) => {
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
            placeholder="Enter public key (base32 or 24 words)..."
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

      {output && (
        <div>
          <label style={{ 
            display: 'block', 
            marginBottom: '8px', 
            fontSize: '14px', 
            fontWeight: '500', 
            color: '#555' 
          }}>
            Output:
          </label>
          <div style={{
            backgroundColor: '#fafafa',
            border: '1px solid #e0e0e0',
            borderRadius: '6px',
            padding: '15px',
            fontFamily: 'monospace',
            fontSize: '13px',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            position: 'relative'
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div style={{ flex: 1 }}>{output}</div>
              {output !== 'Encrypting...' && output !== 'Decrypting...' && (
                <button
                  onClick={onCopyOutput}
                  title="Copy output to clipboard"
                  style={{
                    background: 'white',
                    border: '1px solid #e0e0e0',
                    borderRadius: '4px',
                    padding: '4px 8px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontSize: '12px',
                    marginLeft: '10px',
                    flexShrink: 0,
                    transition: 'all 0.2s'
                  }}
                >
                  {copiedOutput ? <IconCheck size={14} /> : <IconCopy size={14} />}
                  {copiedOutput ? 'Copied!' : 'Copy'}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
