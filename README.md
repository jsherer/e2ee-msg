# E2EE MSG - End-to-End Encrypted Messenger

A serverless, browser-based end-to-end encrypted messaging application that runs entirely in your browser. No server, no backend, no data ever leaves your device except the encrypted messages you choose to share.

## Features

- 🔐 **True End-to-End Encryption** - Uses TweetNaCl (NaCl/Curve25519) for asymmetric encryption
- 🔑 **Master Key Protection** - Private keys are encrypted with your master password
- 📝 **BIP39 Word Encoding** - Public keys can be displayed as 24 memorable words for easy sharing
- 💾 **URL Persistence** - Encrypted private keys stored in URL hash for recovery
- 🌐 **Completely Serverless** - Runs 100% in the browser, works offline
- 📦 **Single File Distribution** - Can be distributed as a single HTML file or data URI

## Quick Start

### Online Version
1. Open `dist/index.html` in your browser
2. Enter a master password (this encrypts your private keys)
3. Your keypair is automatically generated
4. Share your public key with others to receive messages
5. Enter their public key to send encrypted messages

### Standalone Version
```bash
npm install
npm run build:standalone
```
This creates:
- `dist/standalone.html` - Single HTML file with everything embedded
- `dist/datauri.txt` - Base64 data URI that can be bookmarked

## How It Works

### Key Generation
- Generates a Curve25519 keypair using TweetNaCl
- Private key is immediately encrypted with your master password
- Public key can be shared in two formats:
  - **Base36**: Compact alphanumeric format
  - **BIP39 Words**: 24 common English words (easier to speak/remember)

### Encryption Process
1. Enter recipient's public key (base36 or words)
2. Type your message
3. Click "Encrypt" to create encrypted message
4. Share the encrypted output with recipient

### Decryption Process
1. Enter sender's public key
2. Paste encrypted message
3. Click "Decrypt" to reveal original message

## Security Features

- **Private keys never exposed**: Always encrypted with master password
- **Fresh nonces**: New nonce for each encryption operation
- **URL hash storage**: Encrypted private key in URL for recovery (requires master password)
- **No external dependencies**: All cryptography runs locally
- **Memory safety**: Keys re-encrypted with new nonces after each operation

## Building from Source

### Prerequisites
- Node.js 14+
- npm

### Development
```bash
npm install
npm run build:watch  # Auto-rebuild on changes
```

### Production Build
```bash
npm run build  # Creates dist/bundle.js
npm run build:standalone  # Creates standalone HTML and data URI
```

## File Structure
```
/app/
├── src/
│   ├── App.tsx           # Main React application
│   ├── index.tsx         # Entry point
│   ├── bip39.ts          # BIP39 word encoding/decoding
│   └── tweetnacl.d.ts    # TypeScript definitions
├── dist/
│   ├── index.html        # Main HTML file
│   ├── bundle.js         # Compiled JavaScript
│   ├── standalone.html   # Single-file version
│   └── datauri.txt       # Base64 data URI
└── tools/
    └── create-datauri.js # Build tool for standalone version
```

## Key Format Examples

**Base36 Format:**
```
3jk2l 9xm4p q8r7s t5u6v wx8y9 za1b2 c3d4e f5g6h...
```

**BIP39 Word Format:**
```
abandon ability able about above absent
absorb abstract absurd abuse access accident
account accuse achieve acid acoustic acquire
across act action actor actress actual
```

## Privacy & Security Notes

- **No server communication**: This app never sends data to any server
- **Local storage only**: Keys exist only in browser memory and URL hash
- **Master key critical**: Loss of master password means loss of private key access
- **Public key sharing**: Only share your PUBLIC key, never your private key
- **Encrypted URL hash**: The hash contains your encrypted (not plain) private key

## Technical Details

- **Encryption**: NaCl box (Curve25519 + XSalsa20 + Poly1305)
- **Key Derivation**: SHA-512 hash of master password (first 32 bytes)
- **Private Key Encryption**: NaCl secretbox with derived key
- **BIP39**: 2048-word English wordlist, 24 words = 256 bits
- **Framework**: React + TypeScript
- **Build Tool**: esbuild
- **Size**: ~206KB standalone HTML

## License

See [LICENSE](LICENSE)

## Disclaimer

Built with TweetNaCl.js and React. Use at your own risk. This is experimental software.
