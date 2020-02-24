package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/CptOfEvilMinions/osquery-memory-forensics/assets"
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

// verifyBinaries input: None
// Verify SHA256 hash of binaries and data in go-bindata module
// verifyBinaries outout: Returns result and error (if any)
func VerifyBinaries(winAppDataDirPath string) (bool, error) {
	var err error

	///////////////////////////////// Hash verification for procdump.exe /////////////////////////////////
	// Calculate hash of byte array
	procDumpByteData, err := assets.Asset("bins/procdump.exe")
	if err != nil {
		return false, err
	}
	h0 := sha256.Sum256(procDumpByteData)
	procDumpByteDataFileHash := hex.EncodeToString(h0[:])
	fmt.Println(procDumpByteDataFileHash)

	// Calculate hash of bianry on disk
	procDumpExecutable, err := ioutil.ReadFile(winAppDataDirPath + "\\" + "byteexec\\procdump.exe")
	h1 := sha256.Sum256(procDumpExecutable)
	procDumpExecutableFileHash := hex.EncodeToString(h1[:])
	fmt.Println(procDumpExecutableFileHash)

	///////////////////////////////// Hash verification for winpmem.exe /////////////////////////////////
	// Calculate hash of byte array
	winPmemByteData, err := assets.Asset("bins/winpmem.exe")
	if err != nil {
		return false, err
	}
	h2 := sha256.Sum256(winPmemByteData)
	winPmemByteDataFileHash := hex.EncodeToString(h2[:])
	fmt.Println(winPmemByteDataFileHash)

	// Calculate hash of bianry on disk
	absFilePath, err := filepath.Abs(winAppDataDirPath + "\\" + "byteexec\\winpmem.exe")
	if err != nil {
		return false, err
	}
	winPmemExecutable, err := ioutil.ReadFile(absFilePath)
	h3 := sha256.Sum256(winPmemExecutable)
	winPmemExecutableFileHash := hex.EncodeToString(h3[:])
	fmt.Println(winPmemExecutableFileHash)

	if (procDumpByteDataFileHash == procDumpExecutableFileHash) && (winPmemByteDataFileHash == winPmemExecutableFileHash) {
		return true, errors.New("sucess")
	}

	return false, err
}
