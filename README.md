# yEnc Control Lines Encryption - Go Implementation

This is the reference Go implementation of the **yEnc Control Lines Encryption Standard**, providing format-preserving encryption for yEnc control lines while maintaining full compatibility with existing yEnc parsers and protocols.

## Overview

The yEnc Control Lines Encryption Standard allows encryption of yEnc control lines (`=ybegin`, `=ypart`, `=yend`) using FF1 format-preserving encryption with Argon2id key derivation. Encrypted control lines maintain the same byte length as the original and contain only valid yEnc alphabet characters, making them indistinguishable from regular yEnc control lines.

## Features

- **Format-Preserving Encryption**: Encrypted control lines maintain exact byte length
- **yEnc Alphabet Compliance**: Uses only valid yEnc characters (253-character set)
- **Strong Security**: Argon2id key derivation with FF1 encryption
- **Deterministic**: Same input always produces same encrypted output
- **Segment Support**: Different encryption keys for multi-part yEnc files
- **Line Ending Preservation**: Maintains CRLF, LF, and CR endings exactly
- **Concurrent Processing**: Efficient encryption using goroutines
- **Data Preservation**: Data lines remain completely unchanged

## Installation

```bash
go get github.com/Tensai75/go-yenc-header-encryption
```

## Usage

### Basic Example

```go
package main

import (
    "fmt"
    "log"

    "github.com/Tensai75/go-yenc-header-encryption"
)

func main() {
    // Original yEnc block
    plaintext := `=ybegin line=128 size=12345 name=file.bin
data line 1
data line 2
=yend size=12345 crc32=abcd1234`

    // Encrypt yEnc control lines
    encrypted, err := yEncHeaderEnc.Encrypt(plaintext, 1, "mypassword")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Encrypted:", encrypted)

    // Decrypt back to original
    decrypted, err := yEncHeaderEnc.Decrypt(encrypted, 1, "mypassword")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Decrypted:", decrypted)

    // Verify round-trip
    fmt.Println("Match:", plaintext == decrypted)
}
```

### Multi-Part yEnc Files

```go
// Different segments use different encryption keys
segment1, _ := yEncHeaderEnc.Encrypt(yencPart1, 1, "password")
segment2, _ := yEncHeaderEnc.Encrypt(yencPart2, 2, "password") // Different key due to segment index

// Decrypt with matching segment numbers
decoded1, _ := yEncHeaderEnc.Decrypt(segment1, 1, "password")
decoded2, _ := yEncHeaderEnc.Decrypt(segment2, 2, "password")
```

## API Reference

### Functions

#### `Encrypt(plaintext string, segmentIndex uint32, password string) (string, error)`

Encrypts yEnc control lines in the provided yEnc block.

**Parameters:**

- `plaintext`: Complete yEnc block including control lines and data
- `segmentIndex`: Segment number for multi-part files (affects encryption keys)
- `password`: Password for Argon2id key derivation

**Returns:** Encrypted yEnc block with encrypted control lines and unchanged data lines.

#### `Decrypt(ciphertext string, segmentIndex uint32, password string) (string, error)`

Decrypts yEnc control lines that were encrypted using the Encrypt function.

**Parameters:**

- `ciphertext`: Encrypted yEnc block
- `segmentIndex`: Segment number used during encryption (must match)
- `password`: Password used during encryption (must match)

**Returns:** Original plaintext yEnc block.

## Security

### Cryptographic Components

- **Key Derivation**: Argon2id with time=1, memory=64MB, threads=4
- **Salt Generation**: SHA-256("yenc-control salt" || password)[0:16]
- **Encryption**: FF1 format-preserving encryption (NIST SP 800-38G)
- **Alphabet**: 253-character yEnc set (excludes 0x00, 0x0A, 0x0D)
- **Tweaks**: Unique per line using HMAC-SHA256(segment + line position)

### Security Properties

- **Semantic Security**: Different tweaks ensure identical lines encrypt differently
- **Domain Separation**: Salt prevents rainbow table attacks
- **Memory-Hard**: Argon2id resists ASIC/GPU attacks
- **Format Preservation**: No information leakage through length changes

## Testing

Run the comprehensive test suite:

```bash
# All tests
go test -v

# Specific test categories
go test -run TestEncryptDecryptRoundTrip -v
go test -run TestEncryptionProperties -v
go test -run TestSplitLineRegex -v

# Benchmarks
go test -bench=. -benchmem
```

### Test Coverage

**Overall Coverage: 87.9%** - Run `go test -cover` to verify

| Function            | Coverage | Status              |
| ------------------- | -------- | ------------------- |
| `alphabet()`        | 100.0%   | ✅ Fully covered    |
| `deriveSalt()`      | 100.0%   | ✅ Fully covered    |
| `deriveMasterKey()` | 100.0%   | ✅ Fully covered    |
| `deriveEncKey()`    | 100.0%   | ✅ Fully covered    |
| `deriveTweak()`     | 100.0%   | ✅ Fully covered    |
| `splitLineRegex()`  | 72.7%    | ⚠️ Partial coverage |
| `Encrypt()`         | 89.7%    | ✅ High coverage    |
| `Decrypt()`         | 83.8%    | ✅ High coverage    |

**Test Categories:**

- ✅ Round-trip encryption/decryption
- ✅ Format-preserving properties validation
- ✅ Different segment handling
- ✅ Password security
- ✅ Edge cases (CRLF, empty lines, invalid input)
- ✅ yEnc alphabet compliance
- ✅ Performance benchmarks
- ✅ All cryptographic functions (100% coverage)

**Note:** Uncovered code primarily consists of error handling paths for rare edge cases. All security-critical functionality has complete test coverage.

## Standards Compliance

This implementation follows the complete **yEnc Control Lines Encryption Standard** specification available at:

🔗 **[https://github.com/Tensai75/yenc-encryption-standards](https://github.com/Tensai75/yenc-encryption-standards)**

## Performance

Typical performance on modern hardware:

```
BenchmarkEncrypt-16                   100     ~12ms/op    67MB/op    495 allocs/op
BenchmarkDecrypt-16                   90      ~12ms/op    67MB/op    609 allocs/op
```

Most time is spent in Argon2id key derivation (by design for security).

## Dependencies

- `github.com/Tensai75/go-fpe-bytes/ff1` - FF1 format-preserving encryption
- `golang.org/x/crypto/argon2` - Argon2id key derivation
- `golang.org/x/sync/errgroup` - Concurrent processing

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure all tests pass and add tests for new functionality.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Tensai75** - [GitHub](https://github.com/Tensai75)

## Related Projects

- [yEnc Encryption Standards](https://github.com/Tensai75/yenc-encryption-standards) - Complete specification
- [go-fpe-bytes](https://github.com/Tensai75/go-fpe-bytes) - FF1 format-preserving encryption library
