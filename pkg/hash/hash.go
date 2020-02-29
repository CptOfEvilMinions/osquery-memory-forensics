package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// calculateSHA256File input: programFilePath which is the file path
// a file that needs a SHA256 hash calculated
// calculateSHA256File output: calculated SHA256 file hash
// If the function fails it will return false and the error
func CalculateSHA256File(programFilePath string) (string, error) {
	// Open file
	f, err := os.Open(programFilePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// Generate SHA256 hash for file
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	// Return SHA256 hash
	return hex.EncodeToString(h.Sum(nil)), nil
}
