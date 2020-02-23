package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/CptOfEvilMinions/osquery-memory-forensics/assets"
	"github.com/getlantern/byteexec"
	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
)

// Global variables for executable pointers
var winPmemExecutable *byteexec.Exec                                                          // Location of WinPmem binary
var procDumpExecutable *byteexec.Exec                                                         // Location of ProcDump binary
var foresincDataDirectory = "C:\\forensics\\data"                                             // Default location to store forensic data
var winAppDataDirPath = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH") + "\\AppData\\Roaming" // Location of binaries on disk

var winPmemExecutableFileHash string  //
var procDumpExecutableFileHash string //

var verification = 1 // This enforces the verification check of memory dump tools on disk

// main input: Takes in user input where the Osquery socket is located
// This function registers this Osquery extension using the user provided socket path
// main output: None
func main() {
	var statusBool bool
	var err error

	fmt.Println(winAppDataDirPath)

	// Extract executables on disk
	statusBool, err = DumpExecutablesToDisk()
	if err != nil && statusBool == false {
		log.Fatalf("Could not extract executables to disk: %w\n", err)
	}

	// Make sure forensic folder exists
	statusBool, err = createForensicsDirectory(foresincDataDirectory)
	if err != nil && statusBool == false {
		log.Fatalf("Could not create forensic directory", err)
	}

	// Extract command line arguments
	flSocketPath := flag.String("socket", "", "path to osqueryd extensions socket")
	flTimeout := flag.Int("timeout", 0, "")
	flag.Int("interval", 0, "")
	flag.Parse()

	// allow for osqueryd to create the socket path
	timeout := time.Duration(*flTimeout) * time.Second
	time.Sleep(2 * time.Second)

	// initializing server objecet
	server, err := osquery.NewExtensionManagerServer("memory_dump", *flSocketPath, osquery.ServerTimeout(timeout))

	// If initializing server fails exit
	if err != nil {
		log.Fatalf("Error creating extension: %w\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a generate function.
	// If server.Run() fails exit
	server.RegisterPlugin(table.NewPlugin("memory_dump", MemoryDumpColumns(), MemoryDumpGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}

}

// MemoryDumpColumns input: None
// MemoryDumpColumns output: returns the columns that our table will return.
func MemoryDumpColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("output_path"),
		table.TextColumn("name"),
		table.IntegerColumn("pid"),
		table.IntegerColumn("full_memory_dump"),
		table.TextColumn("status"),
		table.TextColumn("status_bool"),
		table.IntegerColumn("verification"),
	}
}

// MemoryDumpGenerate input: ctx and query context
// MemoryDumpGenerate output: Returns a map which contains all the values passed into
func MemoryDumpGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var pid = -1
	var statusBool bool
	var status error
	var fullMemoryDump int
	var name string

	// Extract values
	if len(queryContext.Constraints["output_path"].Constraints) == 1 {
		foresincDataDirectory = queryContext.Constraints["output_path"].Constraints[0].Expression
	} else if len(queryContext.Constraints["pid"].Constraints) == 1 {
		pid, status = strconv.Atoi(queryContext.Constraints["pid"].Constraints[0].Expression)
	} else if len(queryContext.Constraints["verification"].Constraints) == 1 {
		verification, status = strconv.Atoi(queryContext.Constraints["verification"].Constraints[0].Expression)
	} else if len(queryContext.Constraints["full_memory_dump"].Constraints) == 1 {
		fullMemoryDump, status = strconv.Atoi(queryContext.Constraints["full_memory_dump"].Constraints[0].Expression)
	} else {
		status = errors.New("Please specify a PID or set full_memory_dump=1")
		statusBool = false
	}

	// Perform memory dump
	if status == nil {
		statusBool, name, status = MemoryDump(foresincDataDirectory, pid)
	}

	// Set status to sucess if no error was passed up
	if status == nil && statusBool == true {
		status = errors.New("sucess")
	}

	// Return result of memory dump
	return []map[string]string{
		{
			"name":             name,
			"output_path":      foresincDataDirectory,
			"status":           status.Error(),
			"status_bool":      strconv.FormatBool(statusBool),
			"verification":     strconv.Itoa(verification),
			"full_memory_dump": strconv.Itoa(fullMemoryDump),
			"pid":              strconv.Itoa(pid),
		},
	}, nil

}

// createForensicsDirectory input: Path to direcctory to save forensic data
// If directory exists it skips, else create it.
// createForensicsDirectory output: Return boolean reult and on failure return error
func createForensicsDirectory(directoryPath string) (bool, error) {
	var err error

	// Get status of directory
	_, err = os.Stat(directoryPath)

	// If directory doesn't exist, create it
	if os.IsNotExist(err) {
		err = os.Mkdir(directoryPath, 0600)
		if err != nil {
			return false, err
		}
		return true, errors.New("sucess")
	}
	return false, err
}

// MemoryDump input: foresincDataDirectory, pid
// If PID is provided it will proceed with a memory dump of that process, else will
// default to a full memory dump
// MemoryDump output: Returns result, name of new dump (if sucessful), and status
func MemoryDump(foresincDataDirectory string, pid int) (bool, string, error) {
	var memoryDumpFilePath string
	var memoryDumpFileName string
	var memoryDumpErr error

	//Verify Binary
	if verification == 1 {
		statusBool, status := verifyBinaries()
		if statusBool == false && status != nil {
			return false, "", status
		}
	}

	// Perform memory dump with winpmem
	// -1 is full memory dump
	// Anything not -1 is process dump
	if pid != -1 {
		memoryDumpFileName = "proc_dump_" + strconv.Itoa(pid) + "_" + strconv.FormatInt(time.Now().Unix(), 10) + ".dmp"
		memoryDumpFilePath = foresincDataDirectory + "\\" + memoryDumpFileName
		cmd := procDumpExecutable.Command("/accepteula", "-ma", strconv.Itoa(pid), memoryDumpFilePath)
		memoryDumpErr = cmd.Run()
	} else {
		memoryDumpFileName = "winpmem" + "_" + strconv.FormatInt(time.Now().Unix(), 10) + ".dmp"
		memoryDumpFilePath = foresincDataDirectory + "\\" + memoryDumpFileName
		cmd := winPmemExecutable.Command("-o", memoryDumpFilePath)
		memoryDumpErr = cmd.Run()
	}

	// Return error of dump
	// No idea why this error code is returned but it seems to work fine
	if memoryDumpErr != nil && memoryDumpErr.Error() != "exit status 4294967294" {
		return false, "", memoryDumpErr
	}

	// Set mempory dump file permissions
	// https://medium.com/@MichalPristas/go-and-file-perms-on-windows-3c944d55dd44
	if err := os.Chmod(memoryDumpFilePath, 0400); err != nil {
		log.Fatalln(err)
	}

	// Calculate SHA256 hash
	memoryDumpHash, err := calculateSHA256File(memoryDumpFilePath)
	if err == nil {
		return true, memoryDumpFileName, errors.New(memoryDumpHash)
	}

	return false, "", memoryDumpErr
}

// DumpExecutablesToDisk input: None
// Extracts executables from go-bindata module and writes them to
// disk located at `%APPDATA%\\byteexec\\*.exe`
// DumpExecutablesToDisk output: Returns result and error (if any)
func DumpExecutablesToDisk() (bool, error) {
	// Extract ProdDump executable byte array
	procDumpByteData, err := assets.Asset("bins/procdump.exe")
	if err != nil {
		return false, err
	}

	// Write executable to disk
	procDumpExecutable, err = byteexec.New(procDumpByteData, "procdump")
	if err != nil {
		return false, err
	}

	// Extract WinPmem executable byte array
	WinPmemData, err := assets.Asset("bins/winpmem.exe")
	if err != nil {
		return false, err
	}

	// Write executable to disk
	winPmemExecutable, err = byteexec.New(WinPmemData, "winpmem")
	if err != nil {
		return false, err
	}

	// Verify Binary
	if verification == 1 {
		status, err := verifyBinaries()
		if err != nil {
			return status, err
		}
	}

	// Return pointers to executablse
	return true, nil

}

// calculateSHA256File input: programFilePath which is the file path
// a file that needs a SHA256 hash calculated
// calculateSHA256File output: calculated SHA256 file hash
// If the function fails it will return false and the error
func calculateSHA256File(programFilePath string) (string, error) {
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
func verifyBinaries() (bool, error) {
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
