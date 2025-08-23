# E2EE MSG

Serverless end-to-end encrypted messaging with Signal-style Double Ratchet Protocol that runs entirely in your browser. No server, no tracking, no middleman - just pure cryptographic message exchange with forward secrecy and post-compromise security.

## Features

- 🔐 **End-to-End Encryption** - TweetNaCl (Curve25519, XSalsa20, Poly1305)
- 🔄 **Double Ratchet Protocol** - Signal-style forward secrecy & post-compromise security
- 🔑 **Secure Key Storage** - Private keys encrypted with scrypt (memory-hard KDF) and stored in URL
- 🆔 **User ID** - Unique identifier derived from public key hash
- 📝 **Multiple Key Formats**:
  - Base32 Crockford with 5-character grouping (newlines every 25 chars)
  - BIP39 mnemonic words (24 words = 256 bits, 4 words per line)
  - QR codes for easy scanning
- 📸 **QR Code Scanner** - Built-in camera support for scanning public keys
- 💾 **URL-Based Persistence** - Encrypted keys with anti-rollback protection
- 🎨 **Modern UI** - Clean, responsive design with intuitive first-use experience
- 📊 **Ratchet Visualizer** - Real-time visualization of Double Ratchet state
- 📦 **Standalone Distribution** - Single HTML file, no dependencies
- ✅ **Fully Tested** - Comprehensive test suite including Double Ratchet tests

## Quick Start

### Development
```bash
npm install
npm run dev   # Start development server on http://localhost:3000
```

### Testing
```bash
npm test                    # Run all tests
npm test -- --coverage      # Run with coverage report
npm test -- --watch         # Watch mode for development
```

### Building

```bash
npm run build              # Standard build
npm run build:standalone   # Single HTML file with embedded JS
npm run build:compressed   # LZ-compressed version (smaller)
```

### Output Files
- `dist/bundle.js` - Compiled JavaScript (~320KB minified)
- `dist/standalone.html` - Single HTML file with embedded JS (~321KB)
- `dist/ultra.html` - LZ-compressed single file (smaller, loads faster)
- `dist/datauri.txt` - Base64 data URI (typically too large for browsers)
- `dist/datauri-ultra.txt` - Compressed data URI (still often too large)


## Usage Guide

### First Time Setup
1. Open the app in your browser
2. Create a master password (minimum 12 characters)
3. Your keypair is generated automatically
4. Your User ID is displayed (e.g., `XXXX-XXXX-XXXX-XXXX`)
5. The encrypted private key is saved in the URL hash

### Sharing Your Public Key
Choose from three formats:
- **Base32**: `3JK2L 9XM4P Q8R7S...` (compact, easy to type)
- **BIP39 Words**: `abandon ability able...` (24 words, memorable)
- **QR Code**: Visual format for scanning (supports camera scanning)

### Sending Encrypted Messages
1. Get recipient's public key
2. Paste it in "Recipient's Public Key" field
3. Toggle "Ratchet" ON for forward secrecy (default, recommended)
4. Type your message
5. Click "Encrypt" to generate encrypted message
6. Share the encrypted text with recipient

### Receiving Encrypted Messages
1. Get sender's public key
2. Paste it in "Sender's Public Key" field
3. Paste encrypted message
4. Click "Decrypt" to read the message
5. Ratchet protocol auto-detects and maintains session (when using)

### Double Ratchet Protocol
When enabled, provides Signal-level security:
- **Forward Secrecy**: Past messages stay secure even if keys are compromised
- **Post-Compromise Security**: Future messages become secure after key compromise ends
- **Automatic Key Rotation**: Keys change with every message exchange
- **Visual State Tracking**: See ratchet operations in real-time
- **Session Management**: Reset individual or all sessions as needed

### Security Features
- Private keys never leave your device unencrypted
- Master key protected with scrypt (memory-hard KDF)
- URL persistence with anti-rollback protection
- Nonce rotation on lock/unlock for forward secrecy
- Fresh start option for key rotation
- Automatic session management

### Cryptography Details

#### Base Encryption
- **Keypair Generation**: TweetNaCl box keypair (Curve25519)
- **Message Encryption**: nacl.box (public key cryptography)
- **Private Key Protection**: scrypt KDF + nacl.secretbox
- **User ID**: SHA-512 hash of public key (first 8 bytes, formatted)

#### Double Ratchet Protocol
- **DH Ratchet**: Curve25519 ephemeral key exchange
- **Symmetric Ratchet**: SHA-256 based KDF chains
- **Message Keys**: Derived from chain keys, single use
- **Header Encryption**: Includes ephemeral public key and counters
- **Max Skip**: Supports up to 100 out-of-order messages
- **Session Storage**: Encrypted with master key, persisted in localStorage

#### Security Parameters
- **Scrypt**: N=16384, r=8, p=1 (balanced for browser performance)
- **Nonce**: Random 24 bytes per message
- **Anti-Rollback**: Sequence number tracking in URL fragment
- **Forward Secrecy**: Achieved through key deletion after use

### Test Coverage

The application includes comprehensive tests (69 tests total):
- Double Ratchet Protocol tests (14 tests)
- Cryptography and key management tests
- Encoding and format conversion tests
- Component behavior tests
- Integration tests for complete E2E flow

Run tests with: `npm test`
View coverage: `npm test -- --coverage`

## Advanced Topics

### Browser Compatibility
- Modern browsers with Web Crypto API support
- Camera access requires HTTPS for QR scanning
- iOS camera requires explicit permission grant

### Known Limitations
- Data URI exceeds browser limits (64KB max)
- No server = no message relay (direct exchange only)
- Encrypted Keys stored in URL hash (clear on browser history clear)

## Tech Stack

- **Crypto**: TweetNaCl.js (audited, minimal, secure)
- **Frontend**: React 18 + TypeScript 5
- **Testing**: Jest + React Testing Library
- **Build**: esbuild (fast, efficient bundling)
- **QR**: qrcode.react + nimiq/qr-scanner
- **Compression**: LZ-String (for distribution)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new features
4. Ensure all tests pass
5. Submit a pull request

## License

See [LICENSE](LICENSE)

## Security Notice

This is experimental software for educational purposes. While it implements the Signal Double Ratchet Protocol and uses established cryptographic libraries (TweetNaCl), it has not undergone formal security audit. The implementation follows Signal's specifications but should not be considered production-ready without proper review.
