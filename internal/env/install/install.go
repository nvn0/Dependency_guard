// internal/env/install/install.go
package install

import (
	"Dependency_guard/internal/docker"
	"Dependency_guard/internal/env/analyze"
	"Dependency_guard/internal/env/utils"
	"fmt"
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

	_, container_id, err := utils.GetProjectInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project info: %v\n", err)
		return
	}

	fmt.Println("Running secure install...")

	cmd := []string{"npm", "install", libraryName}
	out, errOut, err := docker.ExecInContainer(container_id, cmd)
	if err != nil {
		fmt.Printf("Error installing library %s: %v, stderr: %s\n", libraryName, err, errOut)
	}
	fmt.Printf("Output installing library %s: %s\n", libraryName, out)

	fmt.Println(string(out))
}
