/**
 * Visual representation of the Double Ratchet Protocol state
 */

import React, { useState } from 'react';
import { RatchetState, RatchetOperation } from '../types/ratchet';
import { uint8ArrayToBase36 } from '../utils/encoding';

interface RatchetVisualizerProps {
  currentSession: RatchetState | null;
  operations: RatchetOperation[];
  isProcessing: boolean;
  sessionCount: number;
  onReset?: () => void;
  onClearAll?: () => void;
}

export const RatchetVisualizer: React.FC<RatchetVisualizerProps> = ({
  currentSession,
  operations,
  isProcessing,
  sessionCount,
  onReset,
  onClearAll
}) => {
  const [showDetails, setShowDetails] = useState(false);
  const [showOperations, setShowOperations] = useState(true);

  const formatKey = (key: Uint8Array | null): string => {
    if (!key) return 'none';
    const base36 = uint8ArrayToBase36(key);
    return `${base36.slice(0, 5)}...${base36.slice(-5)}`;
  };

  const formatTimestamp = (timestamp: number): string => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
  };

  const getOperationIcon = (type: RatchetOperation['type']): string => {
    switch (type) {
      case 'init': return '🔑';
      case 'encrypt': return '🔐';
      case 'decrypt': return '🔓';
      case 'dh-ratchet': return '🔄';
      case 'skip-messages': return '⚠️';
      case 'error': return '❌';
      default: return '•';
    }
  };

  const getStatusColor = (): string => {
    if (isProcessing) return '#FFA500'; // Orange
    if (!currentSession) return '#999'; // Gray
    if (currentSession.isInitialized) return '#4CAF50'; // Green
    return '#999';
  };

  const getStatusText = (): string => {
    if (isProcessing) return 'Processing...';
    if (!currentSession) return 'No Active Session';
    if (currentSession.isInitialized) return 'Session Active';
    return 'Not Initialized';
  };

  // Create chain visualization
  const renderChain = (count: number, label: string): JSX.Element => {
    const nodes = [];
    const maxNodes = 10;
    const displayCount = Math.min(count, maxNodes);
    
    for (let i = 0; i < displayCount; i++) {
      const isLast = i === displayCount - 1;
      nodes.push(
        <React.Fragment key={i}>
          <span
            style={{
              display: 'inline-block',
              width: '12px',
              height: '12px',
              borderRadius: '50%',
              backgroundColor: isLast ? getStatusColor() : '#ccc',
              marginRight: '4px',
              transition: 'all 0.3s ease'
            }}
          />
          {i < displayCount - 1 && (
            <span
              style={{
                display: 'inline-block',
                width: '15px',
                height: '2px',
                backgroundColor: '#ccc',
                marginRight: '4px',
                verticalAlign: 'middle'
              }}
            />
          )}
        </React.Fragment>
      );
    }
    
    if (count > maxNodes) {
      nodes.push(
        <span key="more" style={{ marginLeft: '8px', color: '#666' }}>
          ...
        </span>
      );
    }
    
    return (
      <div style={{ marginBottom: '12px' }}>
        <div style={{ fontSize: '12px', color: '#666', marginBottom: '4px' }}>
          {label}
        </div>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          {nodes}
          <span style={{ marginLeft: '12px', fontWeight: 'bold', color: '#333' }}>
            #{count}
          </span>
        </div>
      </div>
    );
  };

  return (
    <div
      style={{
        backgroundColor: 'white',
        borderRadius: '8px',
        padding: '20px',
        marginBottom: '20px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
        transition: 'all 0.3s ease'
      }}
    >
      {/* Header */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '20px',
          borderBottom: '1px solid #eee',
          paddingBottom: '15px'
        }}
      >
        <h3 style={{ margin: 0, fontSize: '18px', color: '#333' }}>
          🔐 Double Ratchet Protocol
        </h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span
            style={{
              padding: '4px 12px',
              borderRadius: '12px',
              backgroundColor: getStatusColor(),
              color: 'white',
              fontSize: '12px',
              fontWeight: 'bold'
            }}
          >
            {getStatusText()}
          </span>
          <span style={{ fontSize: '12px', color: '#666' }}>
            Sessions: {sessionCount}
          </span>
        </div>
      </div>

      {currentSession ? (
        <>
          {/* Session Info */}
          <div
            style={{
              backgroundColor: '#f9f9f9',
              borderRadius: '6px',
              padding: '12px',
              marginBottom: '16px'
            }}
          >
            <div style={{ fontSize: '12px', color: '#666', marginBottom: '8px' }}>
              Session with: {formatKey(currentSession.theirIdentityPublicKey)}
            </div>
            
            {/* Ephemeral Keys */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '1fr 1fr',
                gap: '12px',
                marginTop: '12px'
              }}
            >
              <div>
                <div style={{ fontSize: '11px', color: '#999', marginBottom: '4px' }}>
                  My Ephemeral
                </div>
                <div style={{ fontSize: '12px', fontFamily: 'monospace' }}>
                  {formatKey(currentSession.myCurrentEphemeralKeyPair.publicKey)}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '11px', color: '#999', marginBottom: '4px' }}>
                  Their Ephemeral
                </div>
                <div style={{ fontSize: '12px', fontFamily: 'monospace' }}>
                  {formatKey(currentSession.theirLatestEphemeralPublicKey)}
                </div>
              </div>
            </div>
          </div>

          {/* Message Chains */}
          <div style={{ marginBottom: '16px' }}>
            {renderChain(currentSession.sendMessageCounter, 'Sending Chain')}
            {renderChain(currentSession.receiveMessageCounter, 'Receiving Chain')}
          </div>

          {/* Statistics */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(3, 1fr)',
              gap: '12px',
              marginBottom: '16px'
            }}
          >
            <div
              style={{
                textAlign: 'center',
                padding: '8px',
                backgroundColor: '#f0f0f0',
                borderRadius: '4px'
              }}
            >
              <div style={{ fontSize: '20px', fontWeight: 'bold', color: '#333' }}>
                {currentSession.sendMessageCounter + currentSession.receiveMessageCounter}
              </div>
              <div style={{ fontSize: '11px', color: '#666' }}>Total Messages</div>
            </div>
            <div
              style={{
                textAlign: 'center',
                padding: '8px',
                backgroundColor: '#f0f0f0',
                borderRadius: '4px'
              }}
            >
              <div style={{ fontSize: '20px', fontWeight: 'bold', color: '#333' }}>
                {currentSession.skippedMessageKeys.size}
              </div>
              <div style={{ fontSize: '11px', color: '#666' }}>Skipped Keys</div>
            </div>
            <div
              style={{
                textAlign: 'center',
                padding: '8px',
                backgroundColor: '#f0f0f0',
                borderRadius: '4px'
              }}
            >
              <div style={{ fontSize: '20px', fontWeight: 'bold', color: '#333' }}>
                {currentSession.previousSendCounter}
              </div>
              <div style={{ fontSize: '11px', color: '#666' }}>Previous Chain</div>
            </div>
          </div>

          {/* Advanced Details */}
          {showDetails && (
            <div
              style={{
                marginTop: '12px',
                padding: '12px',
                backgroundColor: '#f9f9f9',
                borderRadius: '4px',
                fontSize: '11px',
                fontFamily: 'monospace'
              }}
            >
              <div>Root Key: {formatKey(currentSession.rootKey)}</div>
              <div>Send Chain: {formatKey(currentSession.sendingChainKey)}</div>
              <div>Recv Chain: {formatKey(currentSession.receivingChainKey)}</div>
            </div>
          )}

          {/* Controls */}
          <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
            <button
              onClick={() => setShowDetails(!showDetails)}
              style={{
                padding: '6px 12px',
                fontSize: '12px',
                backgroundColor: '#f0f0f0',
                border: '1px solid #ddd',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              {showDetails ? 'Hide' : 'Show'} Details
            </button>
            {onReset && (
              <button
                onClick={onReset}
                style={{
                  padding: '6px 12px',
                  fontSize: '12px',
                  backgroundColor: '#ff5252',
                  color: 'white',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer'
                }}
              >
                Reset Session
              </button>
            )}
          </div>
        </>
      ) : (
        <div
          style={{
            textAlign: 'center',
            padding: '40px',
            color: '#999'
          }}
        >
          <div style={{ fontSize: '48px', marginBottom: '12px' }}>🔒</div>
          <div>No active ratchet session</div>
          <div style={{ fontSize: '12px', marginTop: '8px' }}>
            Enter a recipient's public key to initialize a secure session
          </div>
        </div>
      )}

      {/* Operations Log */}
      {operations.length > 0 && (
        <div style={{ marginTop: '20px', borderTop: '1px solid #eee', paddingTop: '16px' }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '12px'
            }}
          >
            <h4 style={{ margin: 0, fontSize: '14px', color: '#666' }}>
              Live Feed
            </h4>
            <button
              onClick={() => setShowOperations(!showOperations)}
              style={{
                padding: '4px 8px',
                fontSize: '11px',
                backgroundColor: 'transparent',
                border: '1px solid #ddd',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              {showOperations ? 'Hide' : 'Show'}
            </button>
          </div>
          
          {showOperations && (
            <div
              style={{
                maxHeight: '150px',
                overflowY: 'auto',
                backgroundColor: '#f9f9f9',
                borderRadius: '4px',
                padding: '8px'
              }}
            >
              {operations.map((op, index) => (
                <div
                  key={`${op.timestamp}-${index}`}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    padding: '4px 0',
                    fontSize: '12px',
                    color: op.type === 'error' ? '#f44336' : '#333',
                    opacity: 1 - (index * 0.1),
                    transition: 'opacity 0.3s ease'
                  }}
                >
                  <span style={{ marginRight: '8px' }}>{getOperationIcon(op.type)}</span>
                  <span style={{ marginRight: '8px', color: '#999', fontSize: '11px' }}>
                    {formatTimestamp(op.timestamp)}
                  </span>
                  <span>{op.details}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Clear All Sessions */}
      {sessionCount > 0 && onClearAll && (
        <div style={{ marginTop: '12px', textAlign: 'center' }}>
          <button
            onClick={onClearAll}
            style={{
              padding: '6px 12px',
              fontSize: '11px',
              backgroundColor: 'transparent',
              color: '#ff5252',
              border: '1px solid #ff5252',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Clear All Sessions ({sessionCount})
          </button>
        </div>
      )}
    </div>
  );
};