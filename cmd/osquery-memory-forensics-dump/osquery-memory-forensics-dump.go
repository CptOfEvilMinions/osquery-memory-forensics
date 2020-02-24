package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/CptOfEvilMinions/osquery-memory-forensics/pkg/dumpers"
	"github.com/CptOfEvilMinions/osquery-memory-forensics/pkg/exes"

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
	statusBool, err = exes.DumpExecutablesToDisk(winPmemExecutable, procDumpExecutable, verification, winAppDataDirPath)
	if err != nil && statusBool == false {
		log.Fatalf("Could not extract executables to disk: %w\n", err)
	}

	// Make sure forensic folder exists
	statusBool, err = dumpers.CreateForensicsDirectory(foresincDataDirectory)
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
		statusBool, name, status = dumpers.MemoryDump(foresincDataDirectory, pid, verification, winAppDataDirPath, winPmemExecutable, procDumpExecutable)
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
