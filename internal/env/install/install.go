// internal/env/install/install.go
package install

import (
	"Dependency_guard/internal/docker"
	"Dependency_guard/internal/env/analyze"
	"Dependency_guard/internal/env/utils"
	"fmt"
	"time"
)

func InstallLib(projectName, libraryName string) {

	fmt.Println("Running a scan on lib:", libraryName)
	new, age, err := analyze.AnalyzeNPMPackage(libraryName)
	if err != nil {
		fmt.Printf("Error analyzing package: %v\n", err)
		return
	}

	// Get config info from file
	config_info, err := utils.GetConfigInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project config: %v\n", err)
		return
	}

	// Get delay from config
	var delay int = config_info.Delay

	if new {
		fmt.Printf("\nWarning: Library %s not old enough to be considered secure to install.\n", libraryName)
		return
	} else if age < time.Duration(delay)*time.Hour {
		fmt.Printf("\nWarning: Library %s is very recent (age: %v), consider waiting before installing. The minimum delay for this project is %d hours.\n", libraryName, age, delay)
		return
	} else {
		fmt.Printf("\nInstalling library: %s\n", libraryName)
	}

	_, container_id, err := utils.GetProjectInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project info: %v\n", err)
		return
	}

	fmt.Println("Running secure install...")

	cmd1 := []string{"mkdir", "-p", "/workspace"}
	_, errOut1, err1 := docker.ExecInContainer(container_id, cmd1)
	if err1 != nil {
		fmt.Printf("Error creating workspace directory: %v, stderr: %s\n", err1, errOut1)
		return
	}

	cmd2 := []string{"cd", "/workspace", "&&", "npm", "install", libraryName}
	out2, errOut2, err2 := docker.ExecInContainer(container_id, cmd2)
	if err2 != nil {
		fmt.Printf("Error installing library %s: %v, stderr: %s\n", libraryName, err2, errOut2)
	}
	fmt.Printf("Output installing library %s: %s\n", libraryName, out2)

	fmt.Println(string(out2))
}
