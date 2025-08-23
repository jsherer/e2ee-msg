import React from 'react';

interface OutputCardProps {
  output: string;
  copiedOutput: boolean;
  onCopyOutput: () => void;
}

export const OutputCard: React.FC<OutputCardProps> = ({ 
  output, 
  copiedOutput, 
  onCopyOutput 
}) => {
  if (!output || output.length === 0) return null;

  const isEncrypted = output.startsWith('Encrypted:');
  const isDecrypted = output.startsWith('Decrypted:');
  
  // Remove the prefix from the actual content
  const displayContent = isEncrypted ? output.replace('Encrypted:\n', '') :
                        isDecrypted ? output.replace('Decrypted:\n', '') :
                        output;
  
  return (
    <div style={{
      backgroundColor: 'white',
      borderRadius: '8px',
      padding: '20px',
      marginTop: '20px',
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)'
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '15px'
      }}>
        <h3 style={{
          margin: 0,
          fontSize: '18px',
          color: '#333',
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          {isEncrypted ? '🔐' : isDecrypted ? '🔓' : '📄'} Output {isEncrypted ? '(Encrypted)' : isDecrypted ? '(Decrypted)' : ''}
        </h3>
        <button
          onClick={onCopyOutput}
          style={{
            background: copiedOutput ? '#4CAF50' : 'white',
            color: copiedOutput ? 'white' : '#666',
            border: '1px solid #e0e0e0',
            borderRadius: '6px',
            padding: '6px 12px',
            cursor: 'pointer',
            fontSize: '13px',
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
            transition: 'all 0.2s'
          }}
        >
          {copiedOutput ? '✓ Copied' : '📋 Copy'}
        </button>
      </div>
      
      <pre style={{
        fontFamily: 'monospace',
        fontSize: '13px',
        backgroundColor: '#f8f8f8',
        padding: '15px',
        borderRadius: '6px',
        overflowX: 'auto',
        margin: 0,
        whiteSpace: 'pre-wrap',
        wordBreak: 'break-all',
        lineHeight: '1.5',
        color: isEncrypted ? '#d73a49' : isDecrypted ? '#22863a' : '#333'
      }}>
        {displayContent}
      </pre>
    </div>
  );
};