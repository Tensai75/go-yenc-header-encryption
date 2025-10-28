package yEncHeaderEnc

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
)

// Test the Alphabet function
func TestAlphabet(t *testing.T) {
	alphabet := Alphabet()

	// Test alphabet length
	if len(alphabet) != 253 {
		t.Errorf("Expected alphabet length 253, got %d", len(alphabet))
	}

	// Test that forbidden characters are not present
	forbiddenChars := []byte{0x00, 0x0A, 0x0D}
	for _, char := range forbiddenChars {
		if bytes.Contains(alphabet, []byte{char}) {
			t.Errorf("Alphabet contains forbidden character 0x%02X", char)
		}
	}

	// Test that alphabet starts with 0x01 and contains expected ranges
	if alphabet[0] != 0x01 {
		t.Errorf("Expected alphabet to start with 0x01, got 0x%02X", alphabet[0])
	}

	// Test that alphabet contains 0xFF (last valid character)
	if alphabet[len(alphabet)-1] != 0xFF {
		t.Errorf("Expected alphabet to end with 0xFF, got 0x%02X", alphabet[len(alphabet)-1])
	}
}

// Test the GenerateSalt function
func TestGenerateSalt(t *testing.T) {
	// Test that salt is generated successfully
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	// Test salt length
	if len(salt) != 16 {
		t.Errorf("Expected salt length 16, got %d", len(salt))
	}

	// Test that all bytes are from yEnc alphabet
	alphabet := Alphabet()
	for i, b := range salt {
		if !bytes.Contains(alphabet, []byte{b}) {
			t.Errorf("Salt byte %d (0x%02X) is not in yEnc alphabet", i, b)
		}
	}

	// Test that multiple calls produce different salts (very high probability)
	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Second GenerateSalt failed: %v", err)
	}

	if bytes.Equal(salt, salt2) {
		t.Error("Two consecutive GenerateSalt calls produced identical salts (extremely unlikely)")
	}

	// Test that no forbidden characters are present
	forbiddenChars := []byte{0x00, 0x0A, 0x0D}
	for i, b := range salt {
		for _, forbidden := range forbiddenChars {
			if b == forbidden {
				t.Errorf("Salt contains forbidden character 0x%02X at position %d", forbidden, i)
			}
		}
	}
}

// Test the DeriveMasterKey function
func TestDeriveMasterKey(t *testing.T) {
	password := "testpassword"
	salt := []byte("1234567890123456") // 16 bytes

	// Test basic functionality
	masterKey := DeriveMasterKey(password, salt)

	// Test master key length
	if len(masterKey) != 32 {
		t.Errorf("Expected master key length 32, got %d", len(masterKey))
	}

	// Test deterministic behavior
	masterKey2 := DeriveMasterKey(password, salt)
	if !bytes.Equal(masterKey, masterKey2) {
		t.Error("DeriveMasterKey is not deterministic")
	}

	// Test different passwords produce different keys
	masterKey3 := DeriveMasterKey("differentpassword", salt)
	if bytes.Equal(masterKey, masterKey3) {
		t.Error("Different passwords produced identical master keys")
	}

	// Test different salts produce different keys
	salt2 := []byte("6543210987654321")
	masterKey4 := DeriveMasterKey(password, salt2)
	if bytes.Equal(masterKey, masterKey4) {
		t.Error("Different salts produced identical master keys")
	}
}

// Test the DeriveEncKey function
func TestDeriveEncKey(t *testing.T) {
	// Create a test master key
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	// Test basic functionality
	encKey := DeriveEncKey(masterKey)

	// Test encryption key length
	if len(encKey) != 32 {
		t.Errorf("Expected encryption key length 32, got %d", len(encKey))
	}

	// Test deterministic behavior
	encKey2 := DeriveEncKey(masterKey)
	if !bytes.Equal(encKey, encKey2) {
		t.Error("DeriveEncKey is not deterministic")
	}

	// Test different master keys produce different encryption keys
	masterKey2 := make([]byte, 32)
	rand.Read(masterKey2)
	encKey3 := DeriveEncKey(masterKey2)
	if bytes.Equal(encKey, encKey3) {
		t.Error("Different master keys produced identical encryption keys")
	}
}

// Test the DeriveTweak function
func TestDeriveTweak(t *testing.T) {
	// Create a test master key
	masterKey := make([]byte, 32)
	rand.Read(masterKey)

	segmentIndex := uint32(1)
	lineIndex := uint32(1)

	// Test basic functionality
	tweak := DeriveTweak(masterKey, segmentIndex, lineIndex)

	// Test tweak length
	if len(tweak) != 8 {
		t.Errorf("Expected tweak length 8, got %d", len(tweak))
	}

	// Test deterministic behavior
	tweak2 := DeriveTweak(masterKey, segmentIndex, lineIndex)
	if !bytes.Equal(tweak, tweak2) {
		t.Error("DeriveTweak is not deterministic")
	}

	// Test different segment indices produce different tweaks
	tweak3 := DeriveTweak(masterKey, 2, lineIndex)
	if bytes.Equal(tweak, tweak3) {
		t.Error("Different segment indices produced identical tweaks")
	}

	// Test different line indices produce different tweaks
	tweak4 := DeriveTweak(masterKey, segmentIndex, 2)
	if bytes.Equal(tweak, tweak4) {
		t.Error("Different line indices produced identical tweaks")
	}

	// Test different master keys produce different tweaks
	masterKey2 := make([]byte, 32)
	rand.Read(masterKey2)
	tweak5 := DeriveTweak(masterKey2, segmentIndex, lineIndex)
	if bytes.Equal(tweak, tweak5) {
		t.Error("Different master keys produced identical tweaks")
	}
}

// Test the NewCipher function
func TestNewCipher(t *testing.T) {
	// Test successful creation
	cipher, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	if cipher == nil {
		t.Fatal("NewCipher returned nil cipher")
	}

	// Test that password is stored
	if cipher.password != "testpassword" {
		t.Errorf("Expected password 'testpassword', got '%s'", cipher.password)
	}

	// Test empty password rejection
	_, err = NewCipher("")
	if err == nil {
		t.Error("NewCipher should reject empty password")
	}
}

// Test the Cipher.initialize function
func TestCipherInitialize(t *testing.T) {
	cipher, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	// Test initialization with empty salt (should generate new salt)
	err = cipher.Initialize("")
	if err != nil {
		t.Fatalf("Initialize with empty salt failed: %v", err)
	}

	// Verify salt was generated
	if len(cipher.salt) != 16 {
		t.Errorf("Expected salt length 16, got %d", len(cipher.salt))
	}

	// Verify other fields are set
	if len(cipher.masterKey) != 32 {
		t.Errorf("Expected master key length 32, got %d", len(cipher.masterKey))
	}

	if len(cipher.encKey) != 32 {
		t.Errorf("Expected encryption key length 32, got %d", len(cipher.encKey))
	}

	if len(cipher.alphabet) != 253 {
		t.Errorf("Expected alphabet length 253, got %d", len(cipher.alphabet))
	}

	// Test initialization with provided salt
	cipher2, _ := NewCipher("testpassword")
	testSalt := "1234567890123456"
	err = cipher2.Initialize(testSalt)
	if err != nil {
		t.Fatalf("Initialize with provided salt failed: %v", err)
	}

	if string(cipher2.salt) != testSalt {
		t.Errorf("Expected salt '%s', got '%s'", testSalt, string(cipher2.salt))
	}

	// Test invalid salt length
	cipher3, _ := NewCipher("testpassword")
	err = cipher3.Initialize("short")
	if err == nil {
		t.Error("Initialize should reject invalid salt length")
	}
}

// Test error handling for createCipher
func TestCreateCipherErrors(t *testing.T) {
	cipher, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	// Uninitialized cipher (missing keys)
	cipher.masterKey = nil
	cipher.encKey = nil
	cipher.alphabet = nil
	_, err = cipher.createCipher(1, 1)
	if err == nil {
		t.Error("createCipher should fail with missing keys/alphabet")
	}

	// Invalid alphabet (empty)
	cipher, _ = NewCipher("testpassword")
	cipher.alphabet = []byte{}
	cipher.masterKey = make([]byte, 32)
	cipher.encKey = make([]byte, 32)
	_, err = cipher.createCipher(1, 1)
	if err == nil {
		t.Error("createCipher should fail with empty alphabet")
	}
}

// Test error handling for EncryptLine
func TestEncryptLineErrors(t *testing.T) {
	cipher, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	// Invalid line (simulate FF1 cipher error)
	cipher, _ = NewCipher("testpassword")
	// Provide a line that is too short or malformed
	_, err = cipher.EncryptLine("", 1, 1)
	if err == nil {
		t.Error("EncryptLine should fail with empty line input")
	}
}

// Test error handling for DecryptLine
func TestDecryptLineErrors(t *testing.T) {
	cipher, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	// Invalid line (too short for salt extraction)
	cipher, _ = NewCipher("testpassword")
	_, err = cipher.DecryptLine("short", 1, 1)
	if err == nil {
		t.Error("DecryptLine should fail with line too short for salt")
	}

	// Malformed line (simulate FF1 cipher error)
	cipher, _ = NewCipher("testpassword")
	// Provide a line that is empty or malformed
	_, err = cipher.DecryptLine("", 1, 2)
	if err == nil {
		t.Error("DecryptLine should fail with empty line input")
	}
}

// TestEncryptDecryptLineRoundTrip verifies that EncryptLine followed by
// DecryptLine returns the original control line, preserving any trailing CR.
func TestEncryptDecryptLineRoundTrip(t *testing.T) {
	cipher, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	// Initialize cipher so per-line operations have keys available
	if err := cipher.Initialize(""); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	cases := []struct {
		name string
		line string
	}{
		{name: "NoCR", line: "=ybegin line=128 size=1024 name=test.txt"},
		{name: "WithCR", line: "=ybegin line=128 size=1024 name=test.txt\r"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := cipher.EncryptLine(tc.line, 1, 1)
			if err != nil {
				t.Fatalf("EncryptLine failed: %v", err)
			}

			if encrypted == tc.line {
				t.Error("EncryptLine did not change the input")
			}

			decrypted, err := cipher.DecryptLine(encrypted, 1, 1)
			if err != nil {
				t.Fatalf("DecryptLine failed: %v", err)
			}

			if decrypted != tc.line {
				t.Errorf("Round-trip mismatch:\nGot:  %q\nWant: %q", decrypted, tc.line)
			}
		})
	}
}

// Test basic encryption and decryption functionality
func TestCipherEncryptDecrypt(t *testing.T) {
	cipher, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	// Test data with different line endings
	testCases := []struct {
		name  string
		input string
	}{
		{
			name:  "Basic yEnc block with LF",
			input: "=ybegin line=128 size=1024 name=test.txt\ndata line 1\ndata line 2\n=yend size=1024 crc32=12345678",
		},
		{
			name:  "Basic yEnc block with CRLF",
			input: "=ybegin line=128 size=1024 name=test.txt\r\ndata line 1\r\ndata line 2\r\n=yend size=1024 crc32=12345678",
		},

		{
			name:  "Multi-part yEnc block",
			input: "=ybegin line=128 size=2048 name=test.txt\n=ypart begin=1 end=1024\ndata content here\n=yend size=1024 part=1 pcrc32=87654321",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test encryption
			encrypted, err := cipher.Encrypt(tc.input, 1)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify encryption changed the control lines
			if encrypted == tc.input {
				t.Error("Encryption did not change the input")
			}

			// Verify salt was prepended to first line
			lines := strings.Split(encrypted, "\n")
			if len(lines[0]) <= len(strings.Split(tc.input, "\n")[0]) {
				t.Error("First line should be longer after salt prepending")
			}

			// Test decryption
			decrypted, err := cipher.Decrypt(encrypted, 1)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify round-trip consistency (with normalized line ending)
			expectedDecrypted := tc.input
			if !strings.HasSuffix(expectedDecrypted, "\n") {
				expectedDecrypted += "\n"
			}

			if decrypted != expectedDecrypted {
				t.Errorf("Round-trip failed:\nOriginal: %q\nDecrypted: %q", expectedDecrypted, decrypted)
			}
		})
	}
}

// Test Decrypt error for first line not starting with =ybegin
func TestDecryptFirstLineNotYbegin(t *testing.T) {
	cipher, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	// Create a block with first line not starting with =ybegin
	firstLine := `=yfoo line=128 size=12345 name=file.bin`
	lastLine := `=yend size=12345 crc32=abcdef12`
	cipher.Initialize("1234567890123456")
	// Encrypt the line to get a valid encrypted block
	eFirstLine, err := cipher.EncryptLine(firstLine, 1, 1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	eLastLine, err := cipher.EncryptLine(lastLine, 1, 3)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	salt := cipher.salt
	encrypted := string(salt) + eFirstLine + "\n" + "<data>" + "\n" + eLastLine
	// Try to decrypt, should get error about first line
	_, err = cipher.Decrypt(encrypted, 1)
	if err == nil || !strings.Contains(err.Error(), "decrypted first line does not start with =ybegin") {
		t.Errorf("Decrypt should fail with 'decrypted first line does not start with =ybegin' error, got: %v", err)
	}
}

// Test encryption with different segment indices
func TestCipherEncryptDifferentSegments(t *testing.T) {
	cipher, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	input := "=ybegin line=128 size=1024 name=test.txt\ndata line\n=yend size=1024 crc32=12345678"

	// Encrypt with different segment indices
	encrypted1, err := cipher.Encrypt(input, 1)
	if err != nil {
		t.Fatalf("Encryption with segment 1 failed: %v", err)
	}

	encrypted2, err := cipher.Encrypt(input, 2)
	if err != nil {
		t.Fatalf("Encryption with segment 2 failed: %v", err)
	}

	// Different segments should produce different encrypted output
	if encrypted1 == encrypted2 {
		t.Error("Different segment indices produced identical encrypted output")
	}

	// Both should decrypt correctly with their respective segment indices
	decrypted1, err := cipher.Decrypt(encrypted1, 1)
	if err != nil {
		t.Fatalf("Decryption of segment 1 failed: %v", err)
	}

	decrypted2, err := cipher.Decrypt(encrypted2, 2)
	if err != nil {
		t.Fatalf("Decryption of segment 2 failed: %v", err)
	}

	expected := input + "\n"
	if decrypted1 != expected || decrypted2 != expected {
		t.Error("Decryption with correct segment indices failed")
	}
}

// Test error cases
func TestCipherErrorCases(t *testing.T) {
	cipher, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	// Test encryption errors
	t.Run("Invalid yEnc block - no =ybegin", func(t *testing.T) {
		_, err := cipher.Encrypt("=ypart begin=1 end=1024\ndata\n=yend size=1024", 1)
		if err == nil {
			t.Error("Should reject input not starting with =ybegin")
		}
	})

	t.Run("Invalid yEnc block - no =yend", func(t *testing.T) {
		_, err := cipher.Encrypt("=ybegin line=128 size=1024 name=test.txt\ndata", 1)
		if err == nil {
			t.Error("Should reject input not ending with =yend")
		}
	})

	// Test decryption errors
	t.Run("Decryption with wrong segment index", func(t *testing.T) {
		encrypted, _ := cipher.Encrypt("=ybegin line=128 size=1024 name=test.txt\ndata\n=yend size=1024", 1)
		_, err := cipher.Decrypt(encrypted, 2)
		if err == nil {
			t.Error("Should fail when decrypting with wrong segment index")
		}
	})

	t.Run("Decryption of too short input", func(t *testing.T) {
		_, err := cipher.Decrypt("short", 1)
		if err == nil {
			t.Error("Should reject input too short to contain salt")
		}
	})
}

// Test multiple cipher instances
func TestMultipleCipherInstances(t *testing.T) {
	// Create cipher for encryption
	cipher1, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher 1 failed: %v", err)
	}

	input := "=ybegin line=128 size=1024 name=test.txt\ndata\n=yend size=1024"

	// Encrypt with first cipher
	encrypted1, err := cipher1.Encrypt(input, 1)
	if err != nil {
		t.Fatalf("Encryption with cipher1 failed: %v", err)
	}

	// Create a new cipher for decryption (realistic usage pattern)
	cipher2, err := NewCipher("testpassword")
	if err != nil {
		t.Fatalf("NewCipher 2 failed: %v", err)
	}

	// Decrypt with second cipher (should work since same password)
	decrypted, err := cipher2.Decrypt(encrypted1, 1)
	if err != nil {
		t.Fatalf("Decryption with cipher2 failed: %v", err)
	}

	expected := input + "\n"
	if decrypted != expected {
		t.Error("Cross-cipher decryption failed")
	}
}

// generateBenchmarkInput creates a realistic yEnc block with 12,000 data lines
// of 128 characters each (~1.5MB total size) for benchmarking.
func generateBenchmarkInput() string {
	const (
		dataLines  = 12000
		lineLength = 128
		totalSize  = dataLines * lineLength
	)

	// Create the yEnc header
	header := fmt.Sprintf("=ybegin line=%d size=%d name=benchmark_file.bin", lineLength, totalSize)

	// Create the yEnc footer
	footer := fmt.Sprintf("=yend size=%d crc32=12345678", totalSize)

	// Pre-allocate slice for better performance
	lines := make([]string, 0, dataLines+2)
	lines = append(lines, header)

	// Generate a repeating pattern for the data line
	pattern := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>? "

	// Create a data line of exactly 128 characters
	var dataLine string
	for len(dataLine) < lineLength {
		remaining := lineLength - len(dataLine)
		if remaining >= len(pattern) {
			dataLine += pattern
		} else {
			dataLine += pattern[:remaining]
		}
	}

	// Generate 12,000 data lines
	for i := 0; i < dataLines; i++ {
		lines = append(lines, dataLine)
	}

	lines = append(lines, footer)

	return strings.Join(lines, "\n")
}

// Benchmark tests
func BenchmarkGenerateSalt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateSalt()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNewCipher(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewCipher("testpassword")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCipherEncrypt(b *testing.B) {
	cipher, err := NewCipher("testpassword")
	if err != nil {
		b.Fatal(err)
	}

	// Generate realistic yEnc block with 12,000 data lines (~1.5MB)
	input := generateBenchmarkInput()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.Encrypt(input, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCipherDecrypt(b *testing.B) {
	cipher, err := NewCipher("testpassword")
	if err != nil {
		b.Fatal(err)
	}

	// Generate realistic yEnc block with 12,000 data lines (~1.5MB)
	input := generateBenchmarkInput()
	encrypted, err := cipher.Encrypt(input, 1)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = cipher.Decrypt(encrypted, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkEncryptLine measures the performance of EncryptLine for a single yEnc control line.
func BenchmarkEncryptLine(b *testing.B) {
	cipher, err := NewCipher("benchpassword")
	if err != nil {
		b.Fatal(err)
	}
	if err := cipher.Initialize(""); err != nil {
		b.Fatal(err)
	}

	line := "=ybegin line=128 size=1024 name=bench.bin"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.EncryptLine(line, 1, uint32(i+1))
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecryptLine measures the performance of DecryptLine for a single yEnc control line.
func BenchmarkDecryptLine(b *testing.B) {
	cipher, err := NewCipher("benchpassword")
	if err != nil {
		b.Fatal(err)
	}
	if err := cipher.Initialize(""); err != nil {
		b.Fatal(err)
	}

	line := "=ybegin line=128 size=1024 name=bench.bin"
	// Prepare an encrypted line to use in the benchmark
	encrypted, err := cipher.EncryptLine(line, 1, 1)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.DecryptLine(encrypted, 1, 1)
		if err != nil {
			b.Fatal(err)
		}
	}
}
