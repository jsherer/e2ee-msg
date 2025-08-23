# E2EE Messenger Tests

All tests for the E2EE Local Messenger application are consolidated in this directory.

## Test Files

### Unit Tests
- `crypto.test.ts` - Cryptographic functions (key generation, encryption/decryption)
- `encoding.test.ts` - Base32 Crockford encoding/decoding utilities
- `clipboard.test.ts` - Clipboard operations for text and images
- `ratchet.test.ts` - Double Ratchet Protocol implementation

### Component Tests
- `LockScreen.test.tsx` - Lock screen component behavior

### Integration Tests
- `e2e-encryption.test.ts` - End-to-end encryption flow testing

## Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm test -- --watch

# Run tests with coverage
npm test -- --coverage

# Run specific test file
npm test -- encoding

# Run tests matching pattern
npm test -- --testNamePattern="should encrypt"
```

## Test Structure

Tests follow standard Jest patterns:
- `describe()` blocks for grouping related tests
- `it()` or `test()` for individual test cases
- `beforeEach()` for setup
- `afterEach()` for cleanup

## Coverage

Test coverage reports are generated in the `coverage/` directory when running with the `--coverage` flag.