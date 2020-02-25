package volatility

import (
	
)

// volatilityImageInfo input:
//
// volatilityImageInfo output:
func volatilityImageInfo(memoryDumpFilePath string) (bool, string, error) {
	cmd := volatilityExecutable.Command("-f", memoryDumpFilePath, "imageinfo", "--output=json")
	cmdOutput, err = cmd.CombinedOutput()

	if err != nil {
		return false, "", volatilityErr
	}
	return true, cmdOutput, nil

}

// volatilityCommands input:
//
// volatilityCommands output:
func volatilityCommands(memoryDumpFilePath string, volatilityProfile string, volatilityCommandLineArgs string) (bool, string, error) {
	cmd: = volatilityExecutable.Command("-f", memoryDumpFilePath, "--profile", volatilityProfile, volatilityCommandLineArgs, "--output=json")
	cmdOutput, err = cmd.CombinedOutput()

	if err != nil {
		return false, "", volatilityErr
	}
	return true, cmdOutput, nil
}


func volatilityPsList(memoryDumpFilePath string, volatilityProfile string) (bool, string, error) {
	cmd: = volatilityExecutable.Command("-f", memoryDumpFilePath, "--profile", volatilityProfile, "pslsit", "--output=json")
	cmdOutput, err = cmd.CombinedOutput()

	if err != nil {
		return false, "", volatilityErr
	}
	return true, cmdOutput, nil
}