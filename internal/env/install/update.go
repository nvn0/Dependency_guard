package install

import (
	"Dependency_guard/internal/docker"
	"Dependency_guard/internal/env/analyze"
	"Dependency_guard/internal/env/utils"
	"fmt"
	"time"
)

func Update(projectName, libraryName string) {
	fmt.Printf("Updating library: %s in project: %s\n", libraryName, projectName)

	_, container_id, err := utils.GetProjectInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project info: %v\n", err)
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

	fmt.Println("Running a scan on lib:", libraryName)
	new, age, err := analyze.AnalyzeNPMPackage(libraryName)
	if err != nil {
		fmt.Printf("Error analyzing package: %v\n", err)
		return
	}

	if new {
		fmt.Printf("\nWarning: Library %s not old enough to be considered secure to update.\n", libraryName)
		return

	} else if age < time.Duration(delay)*time.Hour {
		fmt.Printf("\nWarning: Library %s is very recent (age: %v), consider waiting before updating. The minimum delay for this project is %d hours.\n", libraryName, age, delay)
		return

	} else {
		fmt.Printf("\nUpdating library: %s\n", libraryName)

		cmd1 := []string{"mkdir", "-p", "/workspace"}
		_, errOut1, err1 := docker.ExecInContainer(container_id, cmd1)
		if err1 != nil {
			fmt.Printf("Error creating workspace directory: %v, stderr: %s\n", err1, errOut1)
			return
		}

		cmd := []string{"cd", "/workspace", "&&", "npm", "update", libraryName}
		out, errOut, err := docker.ExecInContainer(container_id, cmd)
		if err != nil {
			fmt.Printf("Error updating library %s: %v, stderr: %s\n", libraryName, err, errOut)
		}
		fmt.Printf("Output updating library %s: %s\n", libraryName, out)
	}
}

func UpdateAll(projectName string) {
	fmt.Printf("Updating all libraries in project: %s\n", projectName)

	_, container_id, err := utils.GetProjectInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project info: %v\n", err)
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

	//get installed libs
	libs, err := docker.GetInstalledNPMLibs(container_id)
	if err != nil {
		fmt.Printf("Error getting installed libraries: %v\n", err)
		return
	}

	// analyze each one and update if possible
	for _, lib := range libs {
		new, age, err := analyze.AnalyzeNPMPackage(lib)
		if err != nil {
			fmt.Printf("Error analyzing package %s: %v\n", lib, err)
			continue
		}

		if new {
			fmt.Printf("\nWarning: Library %s not old enough to be considered secure to update.\n", lib)
			continue
		} else if age < time.Duration(delay)*time.Hour {
			fmt.Printf("\nWarning: Library %s is very recent (age: %v), consider waiting before updating. The minimum delay for this project is %d hours.\n", lib, age, delay)
			continue
		} else {
			fmt.Printf("\nUpdating library: %s\n", lib)

			cmd1 := []string{"mkdir", "-p", "/workspace"}
			_, errOut1, err1 := docker.ExecInContainer(container_id, cmd1)
			if err1 != nil {
				fmt.Printf("Error creating workspace directory: %v, stderr: %s\n", err1, errOut1)
				return
			}

			cmd := []string{"cd", "/workspace", "&&", "npm", "update", lib}
			out, errOut, err := docker.ExecInContainer(container_id, cmd)
			if err != nil {
				fmt.Printf("Error updating library %s: %v, stderr: %s\n", lib, err, errOut)
				continue
			}
			fmt.Printf("Output updating library %s: %s\n", lib, out)
		}
	}
}
