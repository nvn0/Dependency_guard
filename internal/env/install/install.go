// internal/env/install/install.go
package install

import (
	"Dependency_guard/internal/env/analyze"
	"fmt"
	"os/exec"
)

func InstallLib(projectName, libraryName string) {

	fmt.Println("Running a scan on lib:", libraryName)
	new, err := analyze.AnalyzeNPMPackage(libraryName)
	if err != nil {
		fmt.Printf("Error analyzing package: %v\n", err)
		return
	}

	if new {
		fmt.Printf("\nWarning: Library %s not old enough to be considered secure to install.\n", libraryName)
		return
	} else {
		fmt.Printf("\nInstalling library: %s\n", libraryName)
	}

	fmt.Println("Running secure install...")

	cmd := exec.Command("docker", append([]string{
		"exec",
		"safe-env",
	}, "npm", "install", libraryName)...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
	}

	fmt.Println(string(output))
}
