package exes

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/CptOfEvilMinions/osquery-memory-forensics/assets/analyze"
	"github.com/CptOfEvilMinions/osquery-memory-forensics/assets/dump"

	"github.com/getlantern/byteexec"
)

// DumpExecutablesToDisk input: None
// Extracts executables from go-bindata module and writes them to
// disk located at `%APPDATA%\\byteexec\\*.exe`
// DumpExecutablesToDisk output: Returns result and error (if any)
func DumpExecutableToDisk(verification int, winAppDataDirPath string, binName string, extensionType string) (bool, *byteexec.Exec, error) {
	var err error
	var executableByteData []byte

	// Extract data from go-bindata
	if extensionType == "dump" {
		executableByteData, err = dump.Asset("bins/" + extensionType + "/" + binName + ".exe")
	} else if extensionType == "analyze" {
		executableByteData, err = analyze.Asset("bins/" + extensionType + "/" + binName + ".exe")
	}

	/// Write executable to disk
	executable, err := byteexec.New(executableByteData, binName)
	if err != nil {
		return false, nil, err
	}

	// Verify  binary
	if verification == 1 {
		// Generate SHA256 hash of go-bindata executable
		h0 := sha256.Sum256(executableByteData)
		executableByteDataFileHash := hex.EncodeToString(h0[:])
		fmt.Println(executableByteDataFileHash)

		// Calculate hash of bianry on disk
		binExecutable, fileReadErr := ioutil.ReadFile(winAppDataDirPath + "\\" + "byteexec\\" + binName + ".exe")
		if fileReadErr != nil {
			return false, nil, fileReadErr
		}
		h1 := sha256.Sum256(binExecutable)
		binExecutableFileHash := hex.EncodeToString(h1[:])
		fmt.Println(binExecutableFileHash)

		// Compare hashes
		if binExecutableFileHash != executableByteDataFileHash {
			return false, nil, errors.New("Hashes don't match")
		}
	}

	if err == nil {
		return true, executable, nil
	}
	return false, nil, err
}

// verifyBinaries input: None
// Verify SHA256 hash of binaries and data in go-bindata module
// verifyBinaries outout: Returns result and error (if any)
func VerifyBinaries(winAppDataDirPath string, extensionType string) (bool, error) {
	var assetsNames []string
	var err error

	// Extract asset names
	if extensionType == "dump" {
		assetsNames = dump.AssetNames()
	} else if extensionType == "analyze" {
		assetsNames = analyze.AssetNames()
	}

	// Iterate asstes on disk and in bin-godata
	for _, executable := range assetsNames {
		// Extract data from go-bindata
		var executableByteData []byte
		if extensionType == "dump" {
			executableByteData, err = dump.Asset(executable)
		} else if extensionType == "analyze" {
			executableByteData, err = analyze.Asset(executable)
		}

		if err != nil {
			return false, err
		}

		// Generate SHA256 hash of go-bindata executable
		h0 := sha256.Sum256(executableByteData)
		executableByteDataFileHash := hex.EncodeToString(h0[:])
		fmt.Println(executableByteDataFileHash)

		// Calculate hash of bianry on disk
		executableName := strings.SplitN(executable, "/", 3)[2]
		binExecutable, fileErr := ioutil.ReadFile(winAppDataDirPath + "\\" + "byteexec\\" + executableName)
		if err != fileErr {
			return false, err
		}
		h1 := sha256.Sum256(binExecutable)
		binExecutableFileHash := hex.EncodeToString(h1[:])
		fmt.Println(binExecutableFileHash)

		// Compare hashes
		if binExecutableFileHash != executableByteDataFileHash {
			return false, errors.New("Hashes don't match")
		}

	}

	if err == nil {
		return true, nil
	}
	return false, err
}
