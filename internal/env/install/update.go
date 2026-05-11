package install

import (
	"Dependency_guard/internal/docker"
	"Dependency_guard/internal/env/analyze"
	"Dependency_guard/internal/env/utils"
	"fmt"
)

func Update(projectName, libraryName string) {
	fmt.Printf("Updating library: %s in project: %s\n", libraryName, projectName)

	_, container_id, err := utils.GetProjectInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project info: %v\n", err)
		return
	}

	fmt.Println("Running a scan on lib:", libraryName)
	new, err := analyze.AnalyzeNPMPackage(libraryName)
	if err != nil {
		fmt.Printf("Error analyzing package: %v\n", err)
		return
	}

	if new {
		fmt.Printf("\nWarning: Library %s not old enough to be considered secure to update.\n", libraryName)
		return
	} else {
		fmt.Printf("\nUpdating library: %s\n", libraryName)

		cmd := []string{"npm", "update", libraryName}
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

	//get installed libs
	libs, err := docker.GetInstalledNPMLibs(container_id)
	if err != nil {
		fmt.Printf("Error getting installed libraries: %v\n", err)
		return
	}

	// analyze each one and update if possible
	for _, lib := range libs {
		new, err := analyze.AnalyzeNPMPackage(lib)
		if err != nil {
			fmt.Printf("Error analyzing package %s: %v\n", lib, err)
			continue
		}

		if new {
			fmt.Printf("\nWarning: Library %s not old enough to be considered secure to update.\n", lib)
			continue
		} else {
			fmt.Printf("\nUpdating library: %s\n", lib)
			cmd := []string{"npm", "update", lib}
			out, errOut, err := docker.ExecInContainer(container_id, cmd)
			if err != nil {
				fmt.Printf("Error updating library %s: %v, stderr: %s\n", lib, err, errOut)
				continue
			}
			fmt.Printf("Output updating library %s: %s\n", lib, out)
		}
	}
}
