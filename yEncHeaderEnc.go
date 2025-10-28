// This package implements the yEnc Control Lines Encryption Standard in Go.
//
// This is the reference implementation for encrypting and decrypting yEnc control lines
// using FF1 format-preserving encryption with Argon2id key derivation. The implementation
// ensures that encrypted yEnc control lines maintain the same byte length and use only
// characters from the yEnc alphabet.
//
// For the complete yEnc Control Lines Encryption Standard specification, see:
// https://github.com/Tensai75/yenc-encryption-standards
//
// Standard Usage:
//
//	plaintext := `=ybegin line=128 size=12345 name=file.bin
//	data line 1
//	data line 2
//	=yend size=12345 crc32=abcd1234`
//
//	// Create cipher with password
//	cipher, err := NewCipher("password")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Encrypt yEnc control lines
//	encrypted, err := cipher.Encrypt(plaintext, 1)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Decrypt back to original
//	decrypted, err := cipher.Decrypt(encrypted, 1)
//	if err != nil {
//		log.Fatal(err)
//	}
package yEncHeaderEnc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Tensai75/go-fpe-bytes/ff1"
	"golang.org/x/crypto/argon2"
)

// yEncAlphabet defines the 253-character alphabet used for FF1 format-preserving encryption.
//
// This alphabet includes all byte values from 0x01 to 0xFF except:
//   - 0x00 (null byte)
//   - 0x0A (line feed, LF)
//   - 0x0D (carriage return, CR)
const yEncAlphabet = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0B\x0C\x0E\x0F" +
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F" +
	"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F" +
	"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F" +
	"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F" +
	"\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F" +
	"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F" +
	"\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F" +
	"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F" +
	"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F" +
	"\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF" +
	"\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF" +
	"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF" +
	"\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF" +
	"\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF" +
	"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"

// Alphabet returns the standard 253-character yEnc alphabet used for FF1 format-preserving encryption.
// This alphabet excludes null (0x00), line feed (0x0A), and carriage return (0x0D).
//
// Returns:
//   - []byte: 253-character yEnc alphabet for format-preserving encryption
func Alphabet() []byte {
	return []byte(yEncAlphabet)
}

// GenerateSalt generates a cryptographically secure random 16-byte salt using values
// from the yEnc alphabet as required by the standard.
//
// Returns:
//   - []byte: 16-byte cryptographically secure random salt with values from yEnc alphabet
//   - error: Error if the system's random number generator fails
func GenerateSalt() ([]byte, error) {
	alphabet := []byte(yEncAlphabet)
	salt := make([]byte, 16)

	// Generate 16 random bytes, each mapped to the yEnc alphabet
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Map each random byte to the yEnc alphabet (253 characters)
	for i := 0; i < 16; i++ {
		salt[i] = alphabet[int(randomBytes[i])%len(alphabet)]
	}

	return salt, nil
}

// DeriveMasterKey derives a 32-byte master key using Argon2id with security
// parameters: time=1, memory=64MB, threads=4.
//
// Parameters:
//   - password: Password string for key derivation
//   - salt: 16-byte salt for Argon2id
//
// Returns:
//   - []byte: 32-byte master key derived using Argon2id
func DeriveMasterKey(password string, salt []byte) []byte {
	// Argon2id parameters - using standard values for high security
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// DeriveEncKey derives the FF1 encryption key from the master key using
// HMAC-SHA256 with the context string "yenc-control key".
//
// Parameters:
//   - masterKey: 32-byte master key from Argon2id
//
// Returns:
//   - []byte: 32-byte FF1 encryption key derived using HMAC-SHA256
func DeriveEncKey(masterKey []byte) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("yenc-control key"))
	return mac.Sum(nil)
}

// DeriveTweak derives an 8-byte FF1 tweak using HMAC-SHA256 with the master key,
// context string "yenc-control tweak", segment index, and line index.
//
// Parameters:
//   - masterKey: 32-byte master key for HMAC
//   - segmentIndex: Segment number for multi-part files
//   - lineIndex: Line position within the yEnc block
//
// Returns:
//   - []byte: 8-byte FF1 tweak for unique line encryption
func DeriveTweak(masterKey []byte, segmentIndex, lineIndex uint32) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("yenc-control tweak"))

	// Convert segmentIndex and lineIndex to bytes (big-endian)
	segmentBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(segmentBytes, segmentIndex)
	mac.Write(segmentBytes)

	lineBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lineBytes, lineIndex)
	mac.Write(lineBytes)

	hash := mac.Sum(nil)
	return hash[:8] // Return first 8 bytes as tweak
}

// Cipher represents a yEnc Control Lines Encryption cipher with precomputed keys.
// It provides methods to encrypt and decrypt yEnc control lines using FF1
// format-preserving encryption with Argon2id key derivation.
//
// A Cipher instance can be reused for multiple encrypt/decrypt operations
// with the same password, avoiding the expensive key derivation process
// on each operation.
type Cipher struct {
	password  string // Password used for key derivation
	salt      []byte // Salt used for Argon2id key derivation
	masterKey []byte // Master key derived from password using Argon2id
	encKey    []byte // FF1 encryption key derived from master key
	alphabet  []byte // yEnc alphabet for FF1 encryption
	once      sync.Once
}

// NewCipher creates a new Cipher instance with keys derived from the provided password.
//
// Parameters:
//   - password: Password for key derivation using Argon2id
//
// Returns:
//   - *Cipher: Cipher instance ready for encrypt/decrypt operations
//   - error: Error if password is empty or key derivation fails
//
// Example:
//
//	cipher, err := NewCipher("mypassword")
//	if err != nil {
//		return err
//	}
//
//	// Encrypt multiple segments with the same cipher
//	encrypted1, _ := cipher.Encrypt(yencBlock1, 1)
//	encrypted2, _ := cipher.Encrypt(yencBlock2, 2)
func NewCipher(password string) (*Cipher, error) {
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}

	return &Cipher{
		password: password,
	}, nil
}

// Initialize initializes the Cipher by generating or processing the salt,
// deriving the master key and encryption key. This method is intended to be
// called before manual line encryption/decryption.
//
// Parameters:
//   - saltString: Optional 16-byte salt string. If empty, a new random salt is generated.
//
// Returns:
//   - error: Error if salt is invalid or key derivation fails
func (c *Cipher) Initialize(saltString string) error {

	// Process salt
	var salt []byte
	var err error
	if saltString == "" {
		// Generate new random salt
		salt, err = GenerateSalt()
		if err != nil {
			return fmt.Errorf("failed to generate salt: %w", err)
		}
	} else {
		salt = []byte(saltString)
	}
	if len(salt) != 16 {
		return fmt.Errorf("invalid salt length: expected 16 bytes, got %d", len(salt))
	}
	// Store salt
	c.salt = salt

	// Derive masterKey
	c.masterKey = DeriveMasterKey(c.password, salt)

	// Derive encKey
	c.encKey = DeriveEncKey(c.masterKey)

	// Get yEnc alphabet
	c.alphabet = Alphabet()

	return nil
}

// initializeOnce ensures the Cipher is initialized only once.
//
// Parameters:
//   - saltString: Optional 16-byte salt string for initialization
//
// Returns:
//   - error: Error if initialization fails
func (c *Cipher) initializeOnce(saltString string) error {
	var initErr error
	c.once.Do(func() {
		initErr = c.Initialize(saltString)
	})
	return initErr
}

// EncryptLine encrypts a single yEnc control line using FF1 format-preserving encryption.
// This method preserves the original line ending and ensures the output uses only yEnc alphabet characters.
//
// Parameters:
//   - line: The yEnc control line to encrypt (string)
//   - segmentIndex: Segment number for multi-part yEnc files
//   - lineIndex: Line position within the yEnc block
//
// Returns:
//   - string: Encrypted yEnc control line with original line ending
//   - error: Error if encryption fails or input is invalid
//
// Example:
//
//	encryptedLine, err := cipher.EncryptLine("=ybegin line=128 size=1024 name=file.txt", 1, 1)
//	if err != nil {
//	    return err
//	}
func (c *Cipher) EncryptLine(line string, segmentIndex, lineIndex uint32) (string, error) {
	var err error

	// Create FF1 cipher with yEnc alphabet
	cipher, err := c.createCipher(segmentIndex, lineIndex)
	if err != nil {
		return "", err
	}

	var encryptedContent []byte
	var lineEnding string
	if strings.HasSuffix(line, "\r") {
		lineEnding = "\r"
		encryptedContent, err = cipher.Encrypt([]byte(line[0 : len(line)-1]))
	} else {
		lineEnding = ""
		encryptedContent, err = cipher.Encrypt([]byte(line))
	}
	if err != nil {
		return "", fmt.Errorf("failed to encrypt line: %v", err)
	}

	// Return the encrypted line with original line ending
	return string(encryptedContent) + lineEnding, nil
}

// Encrypt encrypts yEnc control lines in the provided yEnc block using the cipher's
// precomputed keys. This method processes a yEnc block and encrypts all yEnc control
// lines (lines starting with "=y") while leaving data lines unchanged.
//
// Parameters:
//   - plaintext: The complete yEnc block as a string, including control lines and data
//   - segmentIndex: Segment number for multi-part yEnc files (affects encryption keys)
//
// Returns:
//   - string: Encrypted yEnc block with encrypted control lines and unchanged data lines
//   - error: Error if the input is invalid or encryption fails
//
// Example:
//
//	cipher, _ := NewCipher("mypassword")
//	input := `=ybegin line=128 size=1024 name=file.txt
//	data content here
//	=yend size=1024`
//
//	encrypted, err := cipher.Encrypt(input, 1)
//	if err != nil {
//		return err
//	}
func (c *Cipher) Encrypt(plaintext string, segmentIndex uint32) (string, error) {

	// Initialize cipher (generate salt if not already initialized)
	err := c.initializeOnce("")
	if err != nil {
		return "", err
	}

	// Trim whitespace
	plaintext = strings.TrimSpace(plaintext)

	// Split the yEnc block into lines
	lines := strings.Split(plaintext, "\n")

	// Process lines from the beginning until we hit a non-yEnc control line
	for i, line := range lines {
		if strings.HasPrefix(line, "=y") {
			if i == 0 && strings.HasPrefix(line, "=ybegin") == false {
				return "", fmt.Errorf("first line does not start with =ybegin")
			}
			encryptedLine, err := c.EncryptLine(line, segmentIndex, uint32(i+1))
			if err != nil {
				return "", err
			}
			if i == 0 {
				// Prepend salt to the first line
				lines[i] = string(c.salt) + encryptedLine
			} else {
				lines[i] = encryptedLine
			}
		} else {
			// First non-header line reached, stop processing further lines
			break
		}
	}

	if !strings.HasPrefix(lines[len(lines)-1], "=yend") {
		return "", fmt.Errorf("last line does not start with =yend")
	}
	encryptedLine, err := c.EncryptLine(lines[len(lines)-1], segmentIndex, uint32(len(lines)))
	if err != nil {
		return "", err
	}
	lines[len(lines)-1] = encryptedLine

	// Join the encrypted lines back into a single string and return
	return strings.Join(lines, "\n") + "\n", nil
}

// DecryptLine decrypts a single yEnc control line using FF1 format-preserving encryption.
// This method preserves the original line ending.
//
// Parameters:
//   - line: The encrypted control line to decrypt (string)
//   - segmentIndex: Segment number for multi-part yEnc files
//   - lineIndex: Line position within the yEnc block
//
// Returns:
//   - string: Decrypted yEnc control line with original line ending
//   - error: Error if encryption fails or input is invalid
//
// Example:
//
//	decryptedLine, err := cipher.DecryptLine(<encryptedLine>, 1, 1)
//	if err != nil {
//	    return err
//	}
func (c *Cipher) DecryptLine(line string, segmentIndex, lineIndex uint32) (string, error) {
	var err error

	// Create FF1 cipher with yEnc alphabet
	cipher, err := c.createCipher(segmentIndex, lineIndex)
	if err != nil {
		return "", err
	}

	var decryptedContent []byte
	var lineEnding string
	if strings.HasSuffix(line, "\r") {
		lineEnding = "\r"
		decryptedContent, err = cipher.Decrypt([]byte(line[0 : len(line)-1]))
	} else {
		lineEnding = ""
		decryptedContent, err = cipher.Decrypt([]byte(line))
	}
	if err != nil {
		return "", fmt.Errorf("failed to decrypt line: %v", err)
	}

	// Return the decrypted line with original line ending
	return string(decryptedContent) + lineEnding, nil
}

// Decrypt decrypts yEnc control lines that were encrypted using the Encrypt method.
// This method reverses the encryption process, decrypting yEnc control lines while
// preserving the exact structure and data sections of the original yEnc block.
//
// Parameters:
//   - ciphertext: The encrypted yEnc block containing encrypted control lines
//   - segmentIndex: Segment number used during encryption (must match exactly)
//
// Returns:
//   - string: Original plaintext yEnc block with trailing newline
//   - error: Error if decryption fails or produces invalid control lines
//
// Example:
//
//	cipher, _ := NewCipher("mypassword")
//	// encrypted contains encrypted yEnc control lines
//	decrypted, err := cipher.Decrypt(encrypted, 1)
//	if err != nil {
//		return err
//	}
//	// decrypted is identical to the original plaintext input
func (c *Cipher) Decrypt(ciphertext string, segmentIndex uint32) (string, error) {

	// Trim whitespace
	ciphertext = strings.TrimSpace(ciphertext)

	// Split the yEnc block into lines
	lines := strings.Split(ciphertext, "\n")

	// Process lines from the beginning linearly until we hit a non-yEnc control line
	// but exclude the actual last line to handle it separately
	for i, line := range lines {

		// If this is the first line, extract the salt
		if i+1 == 1 {
			if len(line) < 16 {
				return "", fmt.Errorf("first line too short to contain salt")
			}
			salt := line[:16]
			line = line[16:]

			// Initialize cipher with extracted salt
			err := c.initializeOnce(salt)
			if err != nil {
				return "", err
			}
		}

		// Decrypt the line
		decryptedLine, err := c.DecryptLine(line, segmentIndex, uint32(i+1))
		if err != nil {
			return "", fmt.Errorf("error processing line %d: %v", i+1, err)
		}

		// Check if the decrypted content starts with "=y"
		if strings.HasPrefix(decryptedLine, "=y") {
			// For the first line, ensure it starts with =ybegin
			if i == 0 && strings.HasPrefix(decryptedLine, "=ybegin") == false {
				return "", fmt.Errorf("decrypted first line does not start with =ybegin")
			}
			// This is a yEnc control line, replace with decrypted version
			lines[i] = decryptedLine
		} else {
			// This is the first data line, stop processing from beginning
			// lines[i] already contains the original content, no need to restore
			break
		}
	}

	// Now decrypt the last line (should be =yend)
	decryptedLine, err := c.DecryptLine(lines[len(lines)-1], segmentIndex, uint32(len(lines)))
	if err != nil {
		return "", fmt.Errorf("error processing last line: %v", err)
	}

	// Check if the decrypted content of the last line starts with "=yend"
	if strings.HasPrefix(decryptedLine, "=yend") == false {
		return "", fmt.Errorf("decrypted last line does not start with =yend")
	}
	// Replace with decrypted version
	lines[len(lines)-1] = decryptedLine

	// Join the decrypted lines back into a single string
	return strings.Join(lines, "\n") + "\n", nil
}

func (c *Cipher) createCipher(segmentIndex, lineIndex uint32) (ff1.Cipher, error) {

	// Derive tweak for this line
	tweak := DeriveTweak(c.masterKey, segmentIndex, lineIndex)

	// Create FF1 cipher with yEnc alphabet
	cipher, err := ff1.NewCipherWithAlphabet(c.alphabet, 8, c.encKey, tweak)
	if err != nil {
		return ff1.Cipher{}, fmt.Errorf("failed to create FF1 cipher: %v", err)
	}

	return cipher, nil
}
