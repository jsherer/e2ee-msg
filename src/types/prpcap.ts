/**
 * PRP-Cap Protocol Type Definitions
 * Types for the Pseudorandom Permutation Capability 0-RTT key exchange protocol
 */

/**
 * Epoch parameters for PRP-Cap
 * These define the capability for a time period (e.g., 30 days)
 */
export interface EpochParams {
  // Public parameters (shared via QR code or out-of-band)
  A: Uint8Array;           // s1·G (32 bytes) - public point
  B: Uint8Array;           // s2·G (32 bytes) - public point
  
  // Private parameters (kept secret)
  s1: Uint8Array;          // Semi-static scalar (32 bytes) - retained during epoch
  s2: Uint8Array;          // Ephemeral scalar (32 bytes) - deleted for forward secrecy
  
  // Metadata
  validFrom: number;       // Unix timestamp when epoch becomes valid
  validUntil: number;      // Unix timestamp when epoch expires
  epochId: string;         // Hash(A || B) for identification
}

/**
 * Public epoch information shared via QR code
 */
export interface PublicEpochInfo {
  A: Uint8Array;           // Public point A
  B: Uint8Array;           // Public point B
  validFrom: number;
  validUntil: number;
  epochId: string;
}

/**
 * PRP-Cap identity combining Ed25519 identity with epoch params
 */
export interface PRPCapIdentity {
  // Identity keys (long-term)
  identityPublicKey: Uint8Array;       // Ed25519 public key
  identitySecretKey?: Uint8Array;      // Ed25519 secret key (only for self)
  verificationKey: Uint8Array;          // Ed25519 signing public key
  
  // Current epoch
  currentEpoch: EpochParams | PublicEpochInfo;
  
  // Previous epochs (for transition period)
  previousEpochs?: PublicEpochInfo[];
}

/**
 * Initial message structure for 0-RTT communication
 */
export interface InitialMessage {
  // Message metadata
  version: number;                      // Protocol version
  messageId: Uint8Array;                // Random 16-byte ID
  timestamp: number;                    // Unix timestamp
  
  // Cryptographic components
  ephemeralPublicKey: Uint8Array;       // Sender's ephemeral E = e·G
  capabilityPoint: Uint8Array;          // V_i used for this message
  index: number;                        // Index i used to compute V_i
  
  // Encrypted payload
  ciphertext: Uint8Array;               // AEAD encrypted message
  nonce: Uint8Array;                    // Nonce for AEAD
  
  // Authentication
  signature: Uint8Array;                // Ed25519 signature over entire message
  senderIdentity: Uint8Array;           // Sender's identity public key
}

/**
 * Session states for PRP-Cap protocol
 */
export enum PRPCapSessionState {
  IDLE = 'IDLE',                        // No active session
  INITIATED = 'INITIATED',              // Sent initial message, waiting
  SINGLE_LADDER = 'SINGLE_LADDER',      // Standard 0-RTT mode
  DOUBLE_LADDER = 'DOUBLE_LADDER',      // Both initiated simultaneously
  RATCHETING = 'RATCHETING'             // Transitioned to Double Ratchet
}

/**
 * PRP-Cap session information
 */
export interface PRPCapSession {
  // Session identification
  sessionId: string;                    // Unique session identifier
  peerIdentity: Uint8Array;             // Peer's identity public key
  
  // Session state
  state: PRPCapSessionState;
  createdAt: number;                    // Session creation timestamp
  lastActivity: number;                 // Last message timestamp
  
  // Ladder information
  ladderType: 'single' | 'double' | null;
  myEphemeral?: Uint8Array;             // My ephemeral secret (if initiator)
  theirEphemeral?: Uint8Array;          // Their ephemeral public
  
  // Shared secrets
  sharedSecret?: Uint8Array;            // Single ladder shared secret
  ladder1?: Uint8Array;                 // First ladder (double mode)
  ladder2?: Uint8Array;                 // Second ladder (double mode)
  rootKey?: Uint8Array;                 // Final root key for Double Ratchet
  
  // Message tracking
  sentInitial?: InitialMessage;         // Our initial message (if sent)
  receivedInitial?: InitialMessage;     // Their initial message (if received)
  
  // Index management for replay protection
  usedIndices: Set<number>;              // Indices we've seen from peer
  ourLastIndex?: number;                 // Last index we used
}

/**
 * Configuration for PRP-Cap protocol
 */
export interface PRPCapConfig {
  // Timing parameters
  epochDuration: number;                 // Default: 30 days in milliseconds
  detectionWindow: number;               // Window for double ladder detection (default: 30 seconds)
  
  // Security parameters
  indexSpace: number;                    // Size of index space (default: 2^32)
  maxSkippedIndices: number;             // Maximum indices to track (default: 1000)
  
  // Domain separation strings
  domain: string;                        // Default: "PRP-CAP-v1"
  singleLadderContext: string;          // Default: "SingleLadder"
  doubleLadderContext: string;          // Default: "DoubleLadder"
}

/**
 * Result of processing an initial message
 */
export interface ProcessMessageResult {
  success: boolean;
  session?: PRPCapSession;
  plaintext?: Uint8Array;
  error?: string;
  shouldUpgradeToDouble?: boolean;      // Indicates double ladder detected
}

/**
 * Parameters for creating an initial message
 */
export interface CreateMessageParams {
  recipientIdentity: PRPCapIdentity;    // Recipient's identity and epoch info
  plaintext: Uint8Array;                // Message to encrypt
  myIdentity: PRPCapIdentity;           // Sender's identity for signing
  index?: number;                       // Optional specific index (random if not provided)
}

/**
 * Event types for PRP-Cap protocol
 */
export interface PRPCapEvent {
  type: 'epoch_created' | 'epoch_deleted' | 'session_created' | 
        'ladder_upgraded' | 'transition_to_ratchet' | 'error';
  timestamp: number;
  details: string;
  data?: any;
}

/**
 * Epoch rotation message for in-band updates
 */
export interface EpochRotationMessage {
  newEpoch: PublicEpochInfo;
  signature: Uint8Array;                // Sign(IK, newA || newB || validFrom || oldEpochId)
  oldEpochId: string;                   // Previous epoch being rotated from
}