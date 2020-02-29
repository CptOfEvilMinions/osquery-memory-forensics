package volatility

import (
	"fmt"

	"github.com/getlantern/byteexec"
)

// RunPlugin input: This function takes in a pointer to the executable, a file path to the memory dump,
// name of a Volatility plugin, and the name of an output render
// RunPlugin output: Returns the result of the Volatility plugin
func RunPlugin(volatilityExecutable *byteexec.Exec, memoryDumpFilePath string, volatilityPlugin string, outputRender string) (bool, string, error) {
	cmd := volatilityExecutable.Command("-f", memoryDumpFilePath, "-r", outputRender, volatilityPlugin)
	cmdOutput, err := cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
		return false, "", err
	}
	//fmt.Println(string(cmdOutput))
	return true, string(cmdOutput), nil
}
