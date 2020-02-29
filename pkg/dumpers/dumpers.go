package dumpers

import (
	"errors"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/CptOfEvilMinions/osquery-memory-forensics/pkg/exes"
	"github.com/CptOfEvilMinions/osquery-memory-forensics/pkg/hash"
	"github.com/getlantern/byteexec"
)

// createForensicsDirectory input: Path to direcctory to save forensic data
// If directory exists it skips, else create it.
// createForensicsDirectory output: Return boolean reult and on failure return error
func CreateForensicsDirectory(directoryPath string) (bool, error) {
	var err error

	// Get status of directory
	_, err = os.Stat(directoryPath)

	// If directory doesn't exist, create it
	if os.IsNotExist(err) {
		err = os.Mkdir(directoryPath, 0600)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, err
}

// MemoryDump input: foresincDataDirectory, pid
// If PID is provided it will proceed with a memory dump of that process, else will
// default to a full memory dump
// MemoryDump output: Returns result, name of new dump (if sucessful), and status
func MemoryDump(foresincDataDirectory string, pid int, verification int, winAppDataDirPath string, dumpItExecutable *byteexec.Exec, procDumpExecutable *byteexec.Exec) (bool, string, error) {
	var memoryDumpFilePath string
	var memoryDumpFileName string
	var memoryDumpErr error

	//Verify Binary
	if verification == 1 {
		statusBool, status := exes.VerifyBinaries(winAppDataDirPath, "dump")
		if statusBool == false && status != nil {
			return false, "", status
		}
	}

	// Perform memory dump with DumpIt
	// -1 is full memory dump
	// Anything not -1 is process dump
	if pid != -1 {
		memoryDumpFileName = "proc_dump_" + strconv.Itoa(pid) + "_" + strconv.FormatInt(time.Now().UTC().Unix(), 10) + ".dmp"
		memoryDumpFilePath = foresincDataDirectory + "\\" + memoryDumpFileName
		cmd := procDumpExecutable.Command("/accepteula", "-ma", strconv.Itoa(pid), memoryDumpFilePath)
		memoryDumpErr = cmd.Run()
	} else {
		memoryDumpFileName = "dumpit" + "_" + strconv.FormatInt(time.Now().UTC().Unix(), 10) + ".raw"
		memoryDumpFilePath = foresincDataDirectory + "\\" + memoryDumpFileName
		cmd := dumpItExecutable.Command("-o", memoryDumpFilePath, "--format", "raw")
		memoryDumpErr = cmd.Run()
	}

	// Return error of dump
	// No idea why this error code is returned but it seems to work fine
	if memoryDumpErr != nil && memoryDumpErr.Error() != "exit status 4294967294" && memoryDumpErr.Error() != "exit status 1" {
		return false, "", memoryDumpErr
	}

	// Set mempory dump file permissions
	// https://medium.com/@MichalPristas/go-and-file-perms-on-windows-3c944d55dd44
	if err := os.Chmod(memoryDumpFilePath, 0400); err != nil {
		log.Fatalln(err)
	}

	// Calculate SHA256 hash
	memoryDumpHash, err := hash.CalculateSHA256File(memoryDumpFilePath)
	if err == nil {
		return true, memoryDumpFileName, errors.New(memoryDumpHash)
	}

	return false, "", memoryDumpErr
}
