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
	ps "github.com/mitchellh/go-ps"
)

// CreateForensicsDirectory input: Path to direcctory to save forensic data
// If directory exists it skips, else create it.
// CreateForensicsDirectory output: Return boolean reult and on failure return error
func CreateForensicsDirectory(directoryPath string) (bool, error) {
	var err error

	// Get status of directory
	_, err = os.Stat(directoryPath)

	// If directory doesn't exist, create it
	if os.IsNotExist(err) {
		err = os.MkdirAll(directoryPath, 0600)
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
		// Get process name by PID
		var procName = ""
		p, err := ps.FindProcess(pid)
		if err == nil {
			procName = p.Executable()
		}

		// Create filepath
		memoryDumpFileName = "proc_dump_" + strconv.Itoa(pid) + "_" + procName + "_" + strconv.FormatInt(time.Now().UTC().Unix(), 10) + ".dmp"
		memoryDumpFilePath = foresincDataDirectory + "\\" + memoryDumpFileName

		// /accepteula - accept the EULA license agreement
		// -ma - Write a dump file with all process memory. The default dump format only includes thread and handle information.
		cmd := procDumpExecutable.Command("/accepteula", "-ma", strconv.Itoa(pid), memoryDumpFilePath)
		memoryDumpErr = cmd.Run()
	} else {
		// Get hostname
		var hostname = ""
		h, err := os.Hostname()
		if err == nil {
			hostname = h
		}

		memoryDumpFileName = "dumpit" + "_" + hostname + "_" + strconv.FormatInt(time.Now().UTC().Unix(), 10) + ".bin"
		memoryDumpFilePath = foresincDataDirectory + "\\" + memoryDumpFileName

		// /O - Output path
		// /T - Type of memory dump - set to RAW
		// /Q - Quiet don't prompt user
		cmd := dumpItExecutable.Command("/O", memoryDumpFilePath, "/T", "raw", "/Q")
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
