// This package implements the yEnc Control Lines Encryption Standard in Go.
//
// This is the reference implementation for encrypting and decrypting yEnc control lines
// using FF1 format-preserving encryption with Argon2id key derivation. The implementation
// ensures that encrypted yEnc control lines maintain the same byte length and use only
// characters from the yEnc alphabet, making them indistinguishable from regular yEnc
// control lines to parsers and protocols.
//
// The yEnc Control Lines Encryption Standard provides:
//   - Format-preserving encryption of yEnc control lines (=ybegin, =ypart, =yend)
//   - Preservation of line structure and data sections
//   - Strong cryptographic security using Argon2id and FF1
//   - Deterministic encryption for the same input parameters
//   - Segment-based encryption allowing different keys per yEnc segment
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
//	// Encrypt yEnc control lines
//	encrypted, err := Encrypt(plaintext, 1, "password")
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Decrypt back to original
//	decrypted, err := Decrypt(encrypted, 1, "password")
//	if err != nil {
//		log.Fatal(err)
//	}
package yEncHeaderEnc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"

	"github.com/Tensai75/go-fpe-bytes/ff1"
	"golang.org/x/crypto/argon2"
	"golang.org/x/sync/errgroup"
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

// alphabet returns the standard 253-character yEnc alphabet used for FF1 format-preserving encryption.
// This alphabet excludes null (0x00), line feed (0x0A), and carriage return (0x0D) bytes
// to ensure encrypted content remains compatible with yEnc protocol requirements.
func alphabet() []byte {
	return []byte(yEncAlphabet)
}

// deriveSalt derives a 16-byte salt for Argon2id using SHA-256("yenc-control salt" || password)[0:16].
// This provides domain separation from other uses of the same password.
func deriveSalt(password string) []byte {
	h := sha256.New()
	h.Write([]byte("yenc-control salt"))
	h.Write([]byte(password))
	hash := h.Sum(nil)
	return hash[:16]
}

// deriveMasterKey derives a 32-byte master key using Argon2id with security parameters:
// time=1, memory=64MB, threads=4. This provides strong password-based key derivation.
func deriveMasterKey(password string, salt []byte) []byte {
	// Argon2id parameters - using standard values for high security
	return argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
}

// deriveEncKey derives the FF1 encryption key from the master key using
// HMAC-SHA256 with the context string "yenc-control key".
func deriveEncKey(masterKey []byte) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("yenc-control key"))
	return mac.Sum(nil)
}

// deriveTweak derives an 8-byte FF1 tweak using HMAC-SHA256 with the master key,
// context string "yenc-control tweak", segment index, and line index. This ensures
// different encryption for each control line position and yEnc segment.
func deriveTweak(masterKey []byte, segmentIndex, lineIndex uint32) []byte {
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

// splitLineRegex splits a line into content and line endings using regex ^(.+?)([\r\n]*)$.
// This preserves the original line ending format (CRLF, LF, or CR) during encryption/decryption.
func splitLineRegex(input string) (string, string, error) {
	if input == "" {
		return "", "", fmt.Errorf("input string is empty")
	}

	// Compile the regular expression
	re, err := regexp.Compile(`^(.+?)([\r\n]*)$`)
	if err != nil {
		return "", "", fmt.Errorf("failed to compile regex: %v", err)
	}

	// Find matches
	matches := re.FindStringSubmatch(input)
	if matches == nil {
		return "", "", fmt.Errorf("input string does not match pattern ^(.+)([\\r\\n]*)$")
	}

	// matches[0] is the full match, matches[1] is first group, matches[2] is second group
	if len(matches) != 3 {
		return "", "", fmt.Errorf("unexpected number of matches: expected 3, got %d", len(matches))
	}

	return matches[1], matches[2], nil
}

// Encrypt encrypts yEnc control lines according to the yEnc Control Lines Encryption Standard.
//
// This function processes a yEnc block and encrypts all yEnc control lines (lines starting
// with "=y") while leaving data lines unchanged. The encryption is format-preserving,
// meaning encrypted control lines maintain the same byte length as the original and contain
// only valid yEnc alphabet characters.
//
// Parameters:
//   - plaintext: The complete yEnc block as a string, including control lines and data
//   - segmentIndex: Segment number for multi-part yEnc files (affects encryption keys)
//   - password: Password for key derivation using Argon2id
//
// The function uses FF1 format-preserving encryption with a 253-character yEnc alphabet
// that excludes null bytes (0x00), line feed (0x0A), and carriage return (0x0D).
// Each control line is encrypted with a unique tweak derived from the segment index
// and line position, ensuring different encryption for identical control lines.
//
// Processing:
//  1. Derives cryptographic keys using Argon2id with SHA-256 salt derivation
//  2. Splits input into lines and processes yEnc control lines concurrently
//  3. Preserves line endings (CRLF, LF, CR) exactly as in the original
//  4. Handles edge cases like trailing newlines and empty lines
//  5. Encrypts the =yend line separately to ensure proper block termination
//
// Returns the encrypted yEnc block with encrypted control lines and unchanged data lines,
// or an error if the input is invalid or encryption fails.
//
// Example:
//
//	input := `=ybegin line=128 size=1024 name=file.txt
//	data content here
//	=yend size=1024`
//
//	encrypted, err := Encrypt(input, 1, "mypassword")
//	if err != nil {
//		return err
//	}
//	// encrypted contains the same structure with encrypted control lines
func Encrypt(plaintext string, segmentIndex uint32, password string) (string, error) {
	// Get the yEnc alphabet
	alphabet := alphabet()

	// Derive cryptographic components
	salt := deriveSalt(password)
	masterKey := deriveMasterKey(password, salt)
	encKey := deriveEncKey(masterKey)

	// Split the yEnc block into lines
	lines := strings.Split(plaintext, "\n")

	// Get wait group for synchronizing goroutines
	var eg errgroup.Group

	// Define the goroutine function to encrypt a single line
	encryptLine := func(line string, arrayIndex int, lineIndex uint32) error {
		// Derive tweak for this line
		tweak := deriveTweak(masterKey, segmentIndex, lineIndex)

		// Create FF1 cipher with yEnc alphabet
		cipher, err := ff1.NewCipherWithAlphabet(alphabet, 8, encKey, tweak)
		if err != nil {
			return fmt.Errorf("failed to create FF1 cipher: %v", err)
		}

		// Split line into content and line ending
		content, lineEnding, err := splitLineRegex(line)
		if err != nil {
			return fmt.Errorf("failed to split line: %v", err)
		}

		// Encrypt the line content
		result, err := cipher.Encrypt([]byte(content))
		if err != nil {
			return fmt.Errorf("failed to encrypt line: %v", err)
		}

		// Store the encrypted line with original line ending
		lines[arrayIndex] = string(result) + lineEnding

		return nil
	}

	// Process lines from the beginning until we hit a non-yEnc control line
	// but exclude the last line to handle it separately
	for i, line := range lines {
		if strings.HasPrefix(line, "=y") {
			// capture loop variables to avoid closure capturing the iteration variables
			li := line
			arrayIdx := i
			lineIdx := uint32(i + 1) // lineIndex = arrayIndex + 1
			eg.Go(func() error {
				return encryptLine(li, arrayIdx, lineIdx)
			})
		} else {
			// First non-header line reached, stop processing further lines
			break
		}
	}

	// Find the actual last line (=yend) - it might not be the last element if input ended with newline
	lastLineIdx := len(lines) - 1
	for lastLineIdx >= 0 && lines[lastLineIdx] == "" {
		lastLineIdx--
	}

	if lastLineIdx < 0 || !strings.HasPrefix(lines[lastLineIdx], "=yend") {
		return "", fmt.Errorf("last line does not start with =yend")
	}

	lastLine := lines[lastLineIdx]
	lastLineIndex := uint32(lastLineIdx + 1) // lineIndex = arrayIndex + 1
	eg.Go(func() error {
		return encryptLine(lastLine, lastLineIdx, lastLineIndex)
	})

	// Wait for all goroutines to finish and check for errors
	if err := eg.Wait(); err != nil {
		return "", err
	}

	// Join the encrypted lines back into a single string and return
	return strings.Join(lines, "\n"), nil
}

// Decrypt decrypts yEnc control lines that were encrypted using the Encrypt function.
//
// This function reverses the encryption process, decrypting yEnc control lines while
// preserving the exact structure and data sections of the original yEnc block.
// It uses the same cryptographic parameters and algorithms as the Encrypt function
// to ensure perfect round-trip compatibility.
//
// Parameters:
//   - ciphertext: The encrypted yEnc block containing encrypted control lines
//   - segmentIndex: Segment number used during encryption (must match exactly)
//   - password: Password used during encryption (must match exactly)
//
// The function processes the encrypted block sequentially, attempting to decrypt
// each line and validating that decrypted control lines start with "=y" prefixes.
// Lines that don't decrypt to valid yEnc control lines are treated as data lines
// and left unchanged.
//
// Processing:
//  1. Uses the same key derivation as Encrypt (Argon2id with SHA-256)
//  2. Processes lines sequentially from beginning until non-control line found
//  3. Validates each decrypted line starts with "=y" to confirm it's a control line
//  4. Handles the =yend line separately with proper validation
//  5. Preserves all line endings and data sections exactly
//
// The decryption is deterministic - the same ciphertext, segment index, and password
// will always produce the same plaintext result. Wrong parameters will either fail
// with an error or produce invalid yEnc control lines.
//
// Returns the original plaintext yEnc block, or an error if decryption fails or
// produces invalid control lines.
//
// Example:
//
//	// encrypted contains encrypted yEnc control lines
//	decrypted, err := Decrypt(encrypted, 1, "mypassword")
//	if err != nil {
//		return err
//	}
//	// decrypted is identical to the original plaintext input
func Decrypt(ciphertext string, segmentIndex uint32, password string) (string, error) {
	// Get the yEnc alphabet
	alphabet := alphabet()

	// Derive cryptographic components
	salt := deriveSalt(password)
	masterKey := deriveMasterKey(password, salt)
	encKey := deriveEncKey(masterKey)

	// Split the yEnc block into lines
	lines := strings.Split(ciphertext, "\n")

	// Define the function to decrypt a single line
	decryptLine := func(line string, lineIndex uint32) (string, error) {
		// Split line into content and line ending
		content, lineEnding, err := splitLineRegex(line)
		if err != nil {
			return "", fmt.Errorf("failed to split line: %v", err)
		}

		// Derive tweak for this line
		tweak := deriveTweak(masterKey, segmentIndex, lineIndex)

		// Create FF1 cipher with yEnc alphabet
		cipher, err := ff1.NewCipherWithAlphabet(alphabet, 8, encKey, tweak)
		if err != nil {
			return "", fmt.Errorf("failed to create FF1 cipher: %v", err)
		}

		// Attempt to decrypt the line content
		decryptedContent, err := cipher.Decrypt([]byte(content))
		if err != nil {
			return "", fmt.Errorf("failed to decrypt line: %v", err)
		}

		// Return the decrypted line with original line ending
		return string(decryptedContent) + lineEnding, nil
	}

	// Process lines from the beginning linearly until we hit a non-yEnc control line
	// but exclude the actual last line to handle it separately
	for i, line := range lines {
		decryptedLine, err := decryptLine(line, uint32(i+1))
		if err != nil {
			return "", fmt.Errorf("error processing line %d: %v", i+1, err)
		}

		// Check if the decrypted content starts with "=y"
		if strings.HasPrefix(decryptedLine, "=y") {
			// This is a yEnc control line, replace with decrypted version
			lines[i] = decryptedLine
		} else {
			// This is the first data line, stop processing from beginning
			// lines[i] already contains the original content, no need to restore
			break
		}
	}

	// Find the actual last line (=yend) - it might not be the last element if input ended with newline
	lastLineIdx := len(lines) - 1
	for lastLineIdx >= 0 && lines[lastLineIdx] == "" {
		lastLineIdx--
	}

	if lastLineIdx < 0 {
		return "", fmt.Errorf("no non-empty lines found")
	}

	// Now decrypt the last line (should be =yend)
	lastLineIndex := lastLineIdx + 1 // lineIndex = arrayIndex + 1
	decryptedLine, err := decryptLine(lines[lastLineIdx], uint32(lastLineIndex))
	if err != nil {
		return "", fmt.Errorf("error processing last line: %v", err)
	}

	// Check if the decrypted content of the last line starts with "=yend"
	if strings.HasPrefix(decryptedLine, "=yend") {
		// Replace with decrypted version (should start with =yend)
		lines[lastLineIdx] = decryptedLine
	} else {
		return "", fmt.Errorf("decrypted last line does not start with =yend")
	}

	// Join the decrypted lines back into a single string
	return strings.Join(lines, "\n"), nil
}
