# E2EE MSG

Serverless end-to-end encrypted messaging that runs entirely in your browser. No server, no tracking, no middleman - just pure cryptographic message exchange between you and your recipient.

## Features

- 🔐 **End-to-End Encryption** - TweetNaCl (Curve25519, XSalsa20, Poly1305)
- 🔑 **Master Password Protection** - Private keys encrypted with SHA-512 derived key
- 🆔 **User ID** - Unique identifier derived from public key hash
- 📝 **Multiple Key Formats**:
  - Base36 with 5-character grouping
  - BIP39 mnemonic words (24 words = 256 bits)
  - QR codes for easy scanning
- 📸 **QR Code Scanner** - Scan recipient's public key QR code
- 💾 **Persistent Storage** - Encrypted private keys stored in URL hash
- 🎨 **Modern UI** - Clean, responsive design with dark accents
- 📦 **Standalone Distribution** - Single HTML file, no dependencies
- ✅ **Fully Tested** - Comprehensive test suite including E2E encryption tests

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
- `dist/bundle.js` - Compiled JavaScript (205KB minified)
- `dist/standalone.html` - Single HTML file with embedded JS (206KB)
- `dist/ultra.html` - LZ-compressed single file (135KB, 35% smaller)
- `dist/datauri.txt` - Base64 data URI (274KB - too large for browsers)
- `dist/datauri-ultra.txt` - Compressed data URI (139KB - still too large)


## Usage Guide

### First Time Setup
1. Open the app in your browser
2. Create a master password (minimum 12 characters)
3. Your keypair is generated automatically
4. Your User ID is displayed (e.g., `XXXX-XXXX-XXXX-XXXX`)
5. The encrypted private key is saved in the URL hash

### Sharing Your Public Key
Choose from three formats:
- **Base36**: `3jk2l 9xm4p q8r7s...` (compact, easy to type)
- **BIP39 Words**: `abandon ability able...` (24 words, memorable)
- **QR Code**: Visual format for scanning (supports camera scanning)

### Sending Encrypted Messages
1. Get recipient's public key (any format)
2. Paste it in "Recipient's Public Key" field
3. Type your message
4. Click "Encrypt" to generate encrypted message
5. Share the encrypted text with recipient

### Receiving Encrypted Messages
1. Get sender's public key
2. Paste it in "Sender's Public Key" field
3. Paste encrypted message in decrypt field
4. Click "Decrypt" to read the message

### Security Features
- Private keys never leave your device unencrypted
- Master password required to unlock keys
- URL hash persistence (bookmark to save your encrypted key)
- Reset option available on lock screen
- Automatic lock on page reload

## Architecture

### Project Structure
```
src/
├── App.tsx                 # Main app component (185 lines)
├── components/            
│   ├── LockScreen.tsx      # Master password entry
│   ├── KeysDisplay.tsx     # Public/private key display
│   ├── MasterKeyCard.tsx   # Lock/unlock controls
│   ├── EncryptDecryptCard.tsx # Message encryption UI
│   └── QRScannerModal.tsx  # QR code scanner
├── hooks/
│   ├── useKeyManagement.ts # Keypair & persistence logic
│   ├── useCrypto.ts        # Encryption/decryption
│   └── useQRScanner.ts     # Camera & QR scanning
├── utils/
│   ├── crypto.ts           # TweetNaCl wrappers
│   ├── encoding.ts         # Base36 conversions
│   ├── bip39.ts            # BIP39 word encoding
│   └── clipboard.ts        # Copy functionality
└── __tests__/
    ├── integration/
    │   └── e2e-encryption.test.ts  # Full E2E flow tests
    └── ...                 # Component & utility tests
```

### Cryptography Details

- **Keypair Generation**: TweetNaCl box keypair (Curve25519)
- **Message Encryption**: nacl.box (public key cryptography)
- **Private Key Encryption**: nacl.secretbox with SHA-512 derived key
- **User ID**: First 16 bytes of SHA-512 hash of public key
- **Nonce**: Random 24 bytes per message (prepended to ciphertext)

### Test Coverage

The application includes comprehensive tests:
- Unit tests for all utilities and components
- Integration tests for complete E2E encryption flow
- Tests verify encryption, decryption, key exchange, and security

Run tests with: `npm test`

## Advanced Topics

### Ratchet Protocols
See documentation for forward secrecy options:
- [docs/RATCHET.md](docs/RATCHET.md) - Full async double ratchet
- [docs/SIMPLE-RATCHET.md](docs/SIMPLE-RATCHET.md) - One-way hash ratchet

### Browser Compatibility
- Modern browsers with Web Crypto API support
- Camera access requires HTTPS for QR scanning
- iOS camera requires explicit permission grant

### Known Limitations
- Data URI exceeds browser limits (64KB max)
- No server = no message relay (direct exchange only)
- Keys stored in URL hash (clear on browser history clear)

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

MIT - See [LICENSE](LICENSE)

## Security Notice

This is experimental software for educational purposes. While using established cryptographic libraries (TweetNaCl), it has not undergone formal security audit. For production use, consider established messaging protocols like Signal or Matrix.

## Acknowledgments

- [TweetNaCl.js](https://github.com/dchest/tweetnacl-js) for cryptography
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) for word encoding
- React team for the excellent framework
