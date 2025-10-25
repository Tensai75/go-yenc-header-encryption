package yEncHeaderEnc

import (
	"strings"
	"testing"
)

// Test data for various yEnc block formats
var testData = []struct {
	name     string
	input    string
	password string
	segment  uint32
}{
	{
		name:     "Basic yEnc block",
		password: "test_password",
		segment:  1,
		input: `=ybegin line=128 size=12345 name=test.bin
=ypart begin=1 end=5000
data line 1
data line 2
=yend size=12345 crc32=abcd1234`,
	},
	{
		name:     "Simple yEnc block without ypart",
		password: "simple_pass",
		segment:  1,
		input: `=ybegin line=64 size=1024 name=small.txt
first data line
second data line
third data line
=yend size=1024`,
	},
	{
		name:     "Multi-part yEnc block",
		password: "multi_segment_key",
		segment:  2,
		input: `=ybegin line=128 size=50000 name=large.bin
=ypart begin=10001 end=20000
encoded binary data here
more encoded data
even more data
=yend size=10000 part=2 pcrc32=12345678`,
	},
	{
		name:     "yEnc with CRLF line endings",
		password: "crlf_test",
		segment:  1,
		input: "=ybegin line=64 size=100 name=crlf.txt\r\n" +
			"data with crlf\r\n" +
			"more data\r\n" +
			"=yend size=100\r\n",
	},
	{
		name:     "Empty password edge case",
		password: "",
		segment:  1,
		input: `=ybegin line=32 size=50 name=empty_pass.txt
minimal data
=yend size=50`,
	},
}

// TestEncryptDecryptRoundTrip tests that encryption followed by decryption returns the original text
func TestEncryptDecryptRoundTrip(t *testing.T) {
	for _, td := range testData {
		t.Run(td.name, func(t *testing.T) {
			// Encrypt the input
			encrypted, err := Encrypt(td.input, td.segment, td.password)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify encryption actually changed the content
			if encrypted == td.input {
				t.Error("Encryption did not change the input (possible encryption failure)")
			}

			// Decrypt the result
			decrypted, err := Decrypt(encrypted, td.segment, td.password)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify round-trip success
			if decrypted != td.input {
				t.Errorf("Round-trip failed.\nOriginal:\n%s\nDecrypted:\n%s", td.input, decrypted)
			}
		})
	}
}

// TestEncryptionDeterministic tests that encryption with same parameters produces same result
func TestEncryptionDeterministic(t *testing.T) {
	input := `=ybegin line=64 size=100 name=deterministic.txt
test data for deterministic encryption
=yend size=100`
	password := "deterministic_test"
	segment := uint32(1)

	// Encrypt the same input multiple times
	encrypted1, err := Encrypt(input, segment, password)
	if err != nil {
		t.Fatalf("First encryption failed: %v", err)
	}

	encrypted2, err := Encrypt(input, segment, password)
	if err != nil {
		t.Fatalf("Second encryption failed: %v", err)
	}

	// Results should be identical
	if encrypted1 != encrypted2 {
		t.Error("Encryption is not deterministic - same input produced different outputs")
	}
}

// TestDifferentSegments tests that different segment indices produce different encrypted results
func TestDifferentSegments(t *testing.T) {
	input := `=ybegin line=64 size=100 name=segment_test.txt
test data for segment differentiation
=yend size=100`
	password := "segment_test"

	encrypted1, err := Encrypt(input, 1, password)
	if err != nil {
		t.Fatalf("Encryption with segment 1 failed: %v", err)
	}

	encrypted2, err := Encrypt(input, 2, password)
	if err != nil {
		t.Fatalf("Encryption with segment 2 failed: %v", err)
	}

	// Different segments should produce different encrypted results
	if encrypted1 == encrypted2 {
		t.Error("Different segment indices produced identical encrypted results")
	}

	// Both should decrypt correctly to original
	decrypted1, _ := Decrypt(encrypted1, 1, password)
	decrypted2, _ := Decrypt(encrypted2, 2, password)

	if decrypted1 != input || decrypted2 != input {
		t.Error("Decryption failed for different segments")
	}
}

// TestDifferentPasswords tests that different passwords produce different encrypted results
func TestDifferentPasswords(t *testing.T) {
	input := `=ybegin line=64 size=100 name=password_test.txt
test data for password differentiation
=yend size=100`
	segment := uint32(1)

	encrypted1, err := Encrypt(input, segment, "password1")
	if err != nil {
		t.Fatalf("Encryption with password1 failed: %v", err)
	}

	encrypted2, err := Encrypt(input, segment, "password2")
	if err != nil {
		t.Fatalf("Encryption with password2 failed: %v", err)
	}

	// Different passwords should produce different encrypted results
	if encrypted1 == encrypted2 {
		t.Error("Different passwords produced identical encrypted results")
	}
}

// TestWrongPassword tests that decryption with wrong password fails or produces garbage
func TestWrongPassword(t *testing.T) {
	input := `=ybegin line=64 size=100 name=wrong_pass_test.txt
test data for wrong password
=yend size=100`
	correctPassword := "correct_password"
	wrongPassword := "wrong_password"
	segment := uint32(1)

	// Encrypt with correct password
	encrypted, err := Encrypt(input, segment, correctPassword)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Try to decrypt with wrong password
	decrypted, err := Decrypt(encrypted, segment, wrongPassword)
	if err != nil {
		// If decryption fails, that's acceptable behavior
		return
	}

	// If decryption succeeds, the result should not match the original
	if decrypted == input {
		t.Error("Decryption with wrong password should not produce correct result")
	}
}

// TestEmptyInput tests behavior with empty or minimal input
func TestEmptyInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"Empty string", ""},
		{"Just newline", "\n"},
		{"No yEnc headers", "just plain text\nwith no yEnc markers"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Encrypt(test.input, 1, "test")
			if err == nil {
				t.Error("Expected error for invalid yEnc input, but got none")
			}
		})
	}
}

// TestSplitLineRegex tests the regex function for splitting lines
func TestSplitLineRegex(t *testing.T) {
	tests := []struct {
		input           string
		expectedContent string
		expectedEnding  string
		shouldError     bool
	}{
		{"hello world\r\n", "hello world", "\r\n", false},
		{"test line\n", "test line", "\n", false},
		{"no ending", "no ending", "", false},
		{"with cr\r", "with cr", "\r", false},
		{"", "", "", true}, // Empty string should error
	}

	for _, test := range tests {
		content, ending, err := splitLineRegex(test.input)

		if test.shouldError {
			if err == nil {
				t.Errorf("Expected error for input %q, but got none", test.input)
			}
			continue
		}

		if err != nil {
			t.Errorf("Unexpected error for input %q: %v", test.input, err)
			continue
		}

		if content != test.expectedContent {
			t.Errorf("Wrong content for %q: expected %q, got %q", test.input, test.expectedContent, content)
		}

		if ending != test.expectedEnding {
			t.Errorf("Wrong ending for %q: expected %q, got %q", test.input, test.expectedEnding, ending)
		}
	}
}

// TestDataLinesUnchanged tests that data lines are not modified during encryption/decryption
func TestDataLinesUnchanged(t *testing.T) {
	input := `=ybegin line=64 size=100 name=data_test.txt
this is a data line that should not change
another data line with special chars: !@#$%^&*()
third data line with unicode: 你好世界
=yend size=100`

	encrypted, err := Encrypt(input, 1, "test_password")
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	inputLines := strings.Split(input, "\n")
	encryptedLines := strings.Split(encrypted, "\n")

	// Data lines (indices 1, 2, 3) should be unchanged
	for i := 1; i < len(inputLines)-1; i++ {
		if inputLines[i] != encryptedLines[i] {
			t.Errorf("Data line %d was modified during encryption: original=%q, encrypted=%q",
				i, inputLines[i], encryptedLines[i])
		}
	}
}

// TestEncryptionProperties tests that encrypted lines maintain proper format-preserving properties
func TestEncryptionProperties(t *testing.T) {
	// Create alphabet map for fast lookup
	alphabetMap := make(map[byte]bool)
	for _, b := range []byte(yEncAlphabet) {
		alphabetMap[b] = true
	}

	for _, test := range testData {
		t.Run(test.name, func(t *testing.T) {
			encrypted, err := Encrypt(test.input, test.segment, test.password)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			originalLines := strings.Split(test.input, "\n")
			encryptedLines := strings.Split(encrypted, "\n")

			if len(originalLines) != len(encryptedLines) {
				t.Fatalf("Number of lines changed: original=%d, encrypted=%d", len(originalLines), len(encryptedLines))
			}

			for i, originalLine := range originalLines {
				encryptedLine := encryptedLines[i]

				// Only check yEnc control lines (lines starting with "=y")
				if strings.HasPrefix(originalLine, "=y") {
					// Split both lines to separate content from line endings
					origContent, origEnding, err := splitLineRegex(originalLine)
					if err != nil {
						// Handle lines without line endings
						if originalLine != "" {
							origContent = originalLine
							origEnding = ""
						} else {
							continue // Skip empty lines
						}
					}

					encContent, encEnding, err := splitLineRegex(encryptedLine)
					if err != nil {
						// Handle lines without line endings
						if encryptedLine != "" {
							encContent = encryptedLine
							encEnding = ""
						} else {
							continue // Skip empty lines
						}
					}

					// Test 1: Line endings should be preserved
					if origEnding != encEnding {
						t.Errorf("Line %d ending changed: original=%q, encrypted=%q", i, origEnding, encEnding)
					}

					// Test 2: Content length should be preserved (format-preserving encryption)
					if len(origContent) != len(encContent) {
						t.Errorf("Line %d content length changed: original=%d bytes, encrypted=%d bytes",
							i, len(origContent), len(encContent))
					}

					// Test 3: All bytes in encrypted content should be from the yEnc alphabet
					for j, b := range []byte(encContent) {
						if !alphabetMap[b] {
							t.Errorf("Line %d position %d contains invalid byte 0x%02X (not in yEnc alphabet)", i, j, b)
						}
					}

					// Test 4: Encrypted content should be different from original (unless very short)
					if len(origContent) > 1 && origContent == encContent {
						t.Errorf("Line %d was not encrypted (content unchanged): %q", i, origContent)
					}
				}
			}
		})
	}
}

// Benchmark functions
func BenchmarkEncrypt(b *testing.B) {
	input := `=ybegin line=128 size=12345 name=benchmark.bin
=ypart begin=1 end=5000
benchmark data line 1
benchmark data line 2
benchmark data line 3
=yend size=12345 crc32=abcd1234`
	password := "benchmark_password"
	segment := uint32(1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(input, segment, password)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	input := `=ybegin line=128 size=12345 name=benchmark.bin
=ypart begin=1 end=5000
benchmark data line 1
benchmark data line 2
benchmark data line 3
=yend size=12345 crc32=abcd1234`
	password := "benchmark_password"
	segment := uint32(1)

	// Pre-encrypt the data
	encrypted, err := Encrypt(input, segment, password)
	if err != nil {
		b.Fatalf("Pre-encryption failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Decrypt(encrypted, segment, password)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

func BenchmarkEncryptDecryptRoundTrip(b *testing.B) {
	input := `=ybegin line=128 size=12345 name=roundtrip.bin
=ypart begin=1 end=5000
roundtrip data line 1
roundtrip data line 2
=yend size=12345 crc32=abcd1234`
	password := "roundtrip_password"
	segment := uint32(1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := Encrypt(input, segment, password)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}

		_, err = Decrypt(encrypted, segment, password)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

// Benchmark key derivation functions separately
func BenchmarkKeyDerivation(b *testing.B) {
	password := "benchmark_key_derivation"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		salt := deriveSalt(password)
		masterKey := deriveMasterKey(password, salt)
		_ = deriveEncKey(masterKey)
	}
}

func BenchmarkTweakGeneration(b *testing.B) {
	password := "benchmark_tweak"
	salt := deriveSalt(password)
	masterKey := deriveMasterKey(password, salt)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = deriveTweak(masterKey, 1, uint32(i%100))
	}
}
