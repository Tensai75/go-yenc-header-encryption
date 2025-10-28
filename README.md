[![Godoc](https://godoc.org/github.com/Tensai75/go-yenc-header-encryption?status.svg)](http://godoc.org/github.com/Tensai75/go-yenc-header-encryption)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)

# yEnc Control Lines Encryption - Go Implementation

This is the reference Go implementation of the **yEnc Control Lines Encryption Standard**, providing format-preserving encryption for yEnc control lines while maintaining full compatibility with existing yEnc parsers and protocols.

## Overview

The yEnc Control Lines Encryption Standard allows encryption of yEnc control lines (`=ybegin`, `=ypart`, `=yend`) using FF1 format-preserving encryption with Argon2id key derivation. Encrypted control lines maintain the same byte length as the original and contain only valid yEnc alphabet characters.

## Features

- **Format-Preserving Encryption**: Encrypted control lines maintain exact byte length
- **yEnc Alphabet Compliance**: Uses only valid yEnc characters (253-character set)
- **Strong Security**: Argon2id key derivation with FF1 encryption
- **Deterministic**: Same input always produces same encrypted output
- **Segment Support**: Different encryption keys for multi-part yEnc files
- **Line Ending Preservation**: Maintains CRLF and LF endings exactly
- **Salt Integration**: Cryptographically secure salt embedded in encrypted output
- **Data Preservation**: Data lines remain completely unchanged
- **High Performance**: Optimized for large files with minimal memory overhead

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

    // Create cipher with password
    cipher, err := yEncHeaderEnc.NewCipher("mypassword")
    if err != nil {
        log.Fatal(err)
    }

    // Encrypt yEnc control lines
    encrypted, err := cipher.Encrypt(plaintext, 1)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Encrypted:", encrypted)

    // Decrypt back to original
    decrypted, err := cipher.Decrypt(encrypted, 1)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Decrypted:", decrypted)

    // Verify round-trip (note: decrypted adds trailing newline)
    expected := plaintext + "\n"
    fmt.Println("Match:", decrypted == expected)
}
```

### Multi-Part yEnc Files

```go
// Create cipher once for efficiency
cipher, err := yEncHeaderEnc.NewCipher("password")
if err != nil {
    log.Fatal(err)
}

// Example multi-part yEnc segments
part1 := `=ybegin line=128 size=2048 name=file.bin
=ypart begin=1 end=1024
data content for part 1
=yend size=1024 part=1 pcrc32=12345678`

part2 := `=ybegin line=128 size=2048 name=file.bin
=ypart begin=1025 end=2048
data content for part 2
=yend size=1024 part=2 pcrc32=87654321`

// Different segments use different encryption keys automatically
encrypted1, _ := cipher.Encrypt(part1, 1)
encrypted2, _ := cipher.Encrypt(part2, 2) // Different key due to segment index

// Decrypt with matching segment numbers
cipher2, _ := yEncHeaderEnc.NewCipher("password")
decoded1, _ := cipher2.Decrypt(encrypted1, 1)
decoded2, _ := cipher2.Decrypt(encrypted2, 2)
```

## API Reference

### Types

#### `Cipher`

```go
type Cipher struct {
    // Contains internal references and precomputed cryptographic keys for optimal performance
}
```

### Constructor

#### `NewCipher(password string) (*Cipher, error)`

Creates a new Cipher instance with keys derived from the provided password.

**Parameters:**

- `password`: Password for Argon2id key derivation

**Returns:** A Cipher instance ready for multiple encrypt/decrypt operations, or an error if key derivation fails.

### Methods

#### `(c *Cipher) Encrypt(plaintext string, segmentIndex uint32) (string, error)`

Encrypts yEnc control lines in the provided yEnc block using precomputed keys.

**Parameters:**

- `plaintext`: Complete yEnc block including control lines and data
- `segmentIndex`: Segment number for multi-part files (affects encryption keys)

**Returns:** Encrypted yEnc block with encrypted control lines and unchanged data lines.

#### `(c *Cipher) Decrypt(ciphertext string, segmentIndex uint32) (string, error)`

Decrypts yEnc control lines that were encrypted using the Encrypt method.

**Parameters:**

- `ciphertext`: Encrypted yEnc block
- `segmentIndex`: Segment number used during encryption (must match)

**Returns:** Original plaintext yEnc block.

#### `(c *Cipher) Initialize(saltString string) error`

Initializes the cipher by generating or processing the 16-byte salt, deriving the Argon2id master key and the FF1 encryption key. Call this when you want to perform per-line operations (`EncryptLine`/`DecryptLine`) without doing a full block Encrypt/Decrypt which extracts the salt automatically.

**Parameters:**

- `saltString`: Optional 16-byte salt string. If empty, a new random salt is generated.

**Returns:** An error if the salt is invalid or key derivation fails.

#### `(c *Cipher) EncryptLine(line string, segmentIndex, lineIndex uint32) (string, error)`

Encrypts a single yEnc control line using FF1 format-preserving encryption. Preserves any trailing CR and returns the encrypted control line (does not prepend salt).

**Parameters:**

- `line`: The yEnc control line to encrypt (e.g., `=ybegin ...`)
- `segmentIndex`: Segment number for multi-part files (affects key/tweak)
- `lineIndex`: 1-based line index within the block (used to derive tweak)

**Returns:** Encrypted control line or an error.

#### `(c *Cipher) DecryptLine(line string, segmentIndex, lineIndex uint32) (string, error)`

Decrypts a single yEnc control line previously encrypted with `EncryptLine`. Preserves trailing CR and returns the decrypted control line.

**Parameters:**

- `line`: The encrypted control line to decrypt
- `segmentIndex`: Segment number used during encryption
- `lineIndex`: 1-based line index used during encryption

**Returns:** Decrypted control line or an error.

## Security

### Cryptographic Components

- **Key Derivation**: Argon2id with time=1, memory=64MB, threads=4
- **Salt Generation**: 16-byte cryptographically secure random salt from yEnc alphabet
- **Encryption**: FF1 format-preserving encryption (NIST SP 800-38G)
- **Alphabet**: 253-character yEnc set (excludes 0x00, 0x0A, 0x0D)
- **Tweaks**: Unique per line using HMAC-SHA256(segment + line position)
- **Salt Embedding**: Raw salt bytes prepended to first encrypted control line

### Security Properties

- **Semantic Security**: Different tweaks ensure identical lines encrypt differently
- **Domain Separation**: Salt prevents rainbow table attacks
- **Memory-Hard**: Argon2id resists ASIC/GPU attacks
- **Format Preservation**: No information leakage through length changes

## Standards Compliance

This implementation follows the complete **yEnc Control Lines Encryption Standard** specification available at:

🔗 **[https://github.com/Tensai75/yenc-encryption-standards](https://github.com/Tensai75/yenc-encryption-standards)**

## Testing

Run the comprehensive test suite:

```bash
# All tests
go test -v

# Test coverage
go test -cover

# Benchmarks with large test files (~1.5MB)
go test -bench=Benchmark -benchmem
```

### Test Coverage

**Overall Coverage: 91.3%** - Run `go test -cover` to verify

| Function                   | Coverage | Status                |
| -------------------------- | -------- | --------------------- |
| `Alphabet()`               | 100.0%   | ✅ Fully covered      |
| `GenerateSalt()`           | 88.9%    | ✅ High coverage      |
| `DeriveMasterKey()`        | 100.0%   | ✅ Fully covered      |
| `DeriveEncKey()`           | 100.0%   | ✅ Fully covered      |
| `DeriveTweak()`            | 100.0%   | ✅ Fully covered      |
| `NewCipher()`              | 100.0%   | ✅ Fully covered      |
| `(*Cipher).Initialize()`   | 88.2%    | ✅ High coverage      |
| `(*Cipher).EncryptLine()`  | 92.9%    | ✅ Excellent coverage |
| `(*Cipher).Encrypt()`      | 87.0%    | ✅ High coverage      |
| `(*Cipher).DecryptLine()`  | 92.9%    | ✅ Excellent coverage |
| `(*Cipher).Decrypt()`      | 88.5%    | ✅ High coverage      |
| `(*Cipher).createCipher()` | 100.0%   | ✅ Fully covered      |

**Test Categories:**

- ✅ Core function testing (all cryptographic primitives)
- ✅ Round-trip encryption/decryption with Cipher API
- ✅ Format-preserving properties validation
- ✅ Different segment indexing and multi-part files
- ✅ Cross-cipher instance compatibility
- ✅ Error handling and edge cases
- ✅ Line ending preservation (LF and CRLF)
- ✅ yEnc alphabet compliance verification
- ✅ Salt generation and key derivation security
- ✅ Benchmark tests with performance validation

**Note:** The 8.7% uncovered code consists primarily of error handling paths for rare system-level failures (e.g., RNG failures, memory allocation errors) and defensive validation code. All security-critical functionality has complete test coverage.

## Performance

Benchmark results on modern hardware (AMD Ryzen 7 5800X) with large yEnc files (~1.5MB, 12,000 data lines):

| Benchmark    | Iterations    | Time/Op  | Memory/Op | Allocs/Op |
| ------------ | ------------- | -------- | --------- | --------- |
| GenerateSalt | 10,986,676    | 109.2 ns | 16 B      | 1         |
| NewCipher    | 1,000,000,000 | 0.2 ns   | 0 B       | 0         |
| Encrypt      | 2,823         | 441.0 μs | 3.33 MB   | 175       |
| Decrypt      | 2,661         | 445.8 μs | 3.31 MB   | 292       |
| EncryptLine  | 125,492       | 8.115 μs | 4,539 B   | 84        |
| DecryptLine  | 126,086       | 8.002 μs | 4,522 B   | 84        |

### Performance Analysis

- **Salt Generation (`GenerateSalt`)**: ~109ns per salt

  - Fast cryptographically secure random generation
  - Maps to yEnc alphabet efficiently

- **Cipher Creation (`NewCipher`)**: ~0.2ns per instance

  - Lightweight object creation (initialization deferred)
  - No expensive operations until first encrypt/decrypt

- **Encryption**: ~441μs per 1.5MB file

  - Efficient processing of yEnc control lines
  - High throughput: ~3.4 GB/s effective processing speed
  - Memory efficient: 175 allocations for large files

- **Decryption**: ~446μs per 1.5MB file

  - Includes salt extraction and key derivation
  - Consistent performance with encryption
  - Reasonable memory overhead: 292 allocations

- **Per-Line Encryption/Decryption**: ~8.1μs per control line

  - EncryptLine: ~8.115μs/op (125,492 iters), ~4.54KB/op, 84 allocs/op
  - DecryptLine: ~8.002μs/op (126,086 iters), ~4.52KB/op, 84 allocs/op
  - Useful when doing many individual control-line operations (e.g., streaming or patching headers)

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
