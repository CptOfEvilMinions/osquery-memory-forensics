package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/CptOfEvilMinions/osquery-memory-forensics/pkg/exes"
	"github.com/CptOfEvilMinions/osquery-memory-forensics/pkg/volatility"

	"github.com/getlantern/byteexec"
	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
)

var volatilityExecutable *byteexec.Exec                                                       // Location of Volatility binary
var foresincDataDirectory = "C:\\forensics\\data"                                             // Default location to store forensic data
var winAppDataDirPath = os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH") + "\\AppData\\Roaming" // Location of binaries on disk

var verification = 1 // This enforces the verification check of memory dump tools on disk

// main input: Takes in user input where the Osquery socket is located
// This function registers this Osquery extension using the user provided socket path
// main output: None
func main() {
	var statusBool bool
	var err error

	//Extract executables on disk
	statusBool, volatilityExecutable, err = exes.DumpExecutableToDisk(verification, winAppDataDirPath, "volatility", "analyze")
	if err != nil || statusBool == false {
		log.Fatalf("Could not extract executable Procdump to disk: %w\n", err)
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
	server, err := osquery.NewExtensionManagerServer("memory_analyze", *flSocketPath, osquery.ServerTimeout(timeout))

	// If initializing server fails exit
	if err != nil {
		log.Fatalf("Error creating extension: %w\n", err)
	}

	// Create and register a new table plugin with the server.
	// table.NewPlugin requires the table plugin name,
	// a slice of Columns and a generate function.
	// If server.Run() fails exit
	server.RegisterPlugin(table.NewPlugin("memory_analyze", MemoryAnalyzeColumns(), MemoryAnalyzeGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}

}

// MemoryAnalyzeColumns input: None
// MemoryAnalyzeColumns output: returns the columns that our table will return.
func MemoryAnalyzeColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("file_path"),
		table.TextColumn("result"),
		table.TextColumn("plugin"),
		table.TextColumn("output_render"),
		table.TextColumn("status"),
		table.TextColumn("status_bool"),
		table.IntegerColumn("verification"),
	}
}

// MemoryAnalyzeGenerate input: ctx and query context
// MemoryAnalyzeGenerate output: Returns a map which contains all the values passed into
// and the results of Volatility
func MemoryAnalyzeGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var memoryDumpFilepath string
	var volatilityPlugin string
	var outputRender = "pretty"
	var result string
	var statusBool bool
	var status error
	var err error

	// Extract values
	if len(queryContext.Constraints["plugin"].Constraints) == 1 {
		volatilityPlugin = queryContext.Constraints["plugin"].Constraints[0].Expression
	}
	if len(queryContext.Constraints["output_render"].Constraints) == 1 {
		outputRender = queryContext.Constraints["output_render"].Constraints[0].Expression
	}
	if len(queryContext.Constraints["verification"].Constraints) == 1 {
		verification, status = strconv.Atoi(queryContext.Constraints["verification"].Constraints[0].Expression)
	}
	if len(queryContext.Constraints["file_path"].Constraints) == 1 {
		memoryDumpFilepath = queryContext.Constraints["file_path"].Constraints[0].Expression
	} else {
		status = errors.New("Please specify a PID or set full_memory_dump=1")
		statusBool = false
	}

	// Analysis with Volatility
	statusBool, result, status = volatility.RunPlugin(volatilityExecutable, memoryDumpFilepath, volatilityPlugin, outputRender)
	if err != nil {
		status = err
	}

	// Set status to sucess if no error was passed up
	if status == nil && statusBool == true {
		status = errors.New("sucess")
	}

	// Return result of memory dump
	return []map[string]string{
		{
			"file_path":     memoryDumpFilepath,
			"result":        result,
			"plugin":        volatilityPlugin,
			"output_render": outputRender,
			"status":        status.Error(),
			"status_bool":   strconv.FormatBool(statusBool),
			"verification":  strconv.Itoa(verification),
		},
	}, nil

}
