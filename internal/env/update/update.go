package update

import (
	"Dependency_guard/internal/docker"
	"Dependency_guard/internal/env/analyze"
	"Dependency_guard/internal/env/utils"
	"fmt"
	"time"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
)

func Update(projectName, libraryName string) {
	fmt.Printf("Updating library: %s in project: %s\n", libraryName, projectName)

	envType, container_id, err := utils.GetProjectInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project info: %v\n", err)
		return
	}

	// temp config
	if envType != "node" && envType != "node-alpine" {
		fmt.Println("Update currently only supports node (npm) projects. Detected environment: " + envType)
		return
	}

	// Get config info from file
	config_info, err := utils.GetConfigInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project config: %v\n", err)
		return
	}

	// Get delay from config
	var delay int = config_info.Install.Delay

	// Get allow_scripts from config
	var allowScripts bool = config_info.Install.AllowScripts

	fmt.Println("Running a scan on lib:", libraryName)
	new, age, latest, sha, err := analyze.AnalyzeNPMPackage(libraryName)
	if err != nil {
		fmt.Printf("Error analyzing package: %v\n", err)
		return
	}

	//get installed libs
	libs, err := docker.GetInstalledNPMLibs(container_id)
	if err != nil {
		fmt.Printf("Error getting installed libraries: %v\n", err)
		return
	}

	// Check if the library is installed in the project
	var l_libName string
	var currentVersion string
	var found bool = false
	for t_libName, libVersion := range libs {
		if t_libName == libraryName {
			fmt.Printf("Package found in project %s: %s (%s)\n", projectName, t_libName, libVersion)
			l_libName = t_libName
			currentVersion = libVersion
			found = true
		}
	}

	if !found {
		fmt.Println("\n" + Yellow + "Info: Package " + libraryName + " not installed in project " + projectName + Reset)
		return
	} else {

		fmt.Println("\n=== Analyzing file changes between versions:", currentVersion, "(current installed)->", latest, "===")
		// File change analysis with the instaled version and the latest version
		_, err = analyze.AnalyzeNewFiles(l_libName, currentVersion, latest, sha)
		if err != nil {
			fmt.Printf("Warning: Error analyzing new files: %v\n", err)
		}

	}

	if new {
		fmt.Printf("\nWarning: Library %s not old enough to be considered secure to update.\n", libraryName)
		return

	} else if age < time.Duration(delay)*time.Hour {
		fmt.Printf("\nWarning: Library %s is very recent (age: %d hours), consider waiting before updating. The minimum delay for this project is %d hours.\n", libraryName, int(age.Round(time.Hour).Hours()), delay)
		return

	} else {

		fmt.Println("\nYou want to proceed with the update? [y/n]")
		var response string
		fmt.Scanln(&response)

		if response != "y" {
			fmt.Println("Update cancelled.")
			return
		}

		fmt.Printf("\nUpdating library: %s\n", libraryName)

		var update_cmd string
		if allowScripts {
			update_cmd = "cd /workspace && npm update " + libraryName
		} else {
			update_cmd = "cd /workspace && npm update --ignore-scripts " + libraryName
		}

		cmd1 := []string{"mkdir", "-p", "/workspace"}
		_, errOut1, err1 := docker.ExecInContainer(container_id, cmd1)
		if err1 != nil {
			fmt.Printf("Error creating workspace directory: %v, stderr: %s\n", err1, errOut1)
			return
		}

		cmd := []string{"sh", "-c", update_cmd}
		out, errOut, err := docker.ExecInContainer(container_id, cmd)
		if err != nil {
			fmt.Printf("Error updating library %s: %v, stderr: %s\n", libraryName, err, errOut)
		}
		fmt.Printf("Output updating library %s: %s\n", libraryName, out)
	}
}

func UpdateAll(projectName string) {
	fmt.Printf("Updating all libraries in project: %s\n", projectName)

	envType, container_id, err := utils.GetProjectInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project info: %v\n", err)
		return
	}

	if envType != "node" && envType != "node-alpine" {
		fmt.Println("Update currently only supports node (npm) projects. Detected environment: " + envType)
		return
	}

	// Get config info from file
	config_info, err := utils.GetConfigInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project config: %v\n", err)
		return
	}

	// Get delay from config
	var delay int = config_info.Install.Delay

	// Get allow_scripts from config
	var allowScripts bool = config_info.Install.AllowScripts

	//get installed libs
	libs, err := docker.GetInstalledNPMLibs(container_id)
	if err != nil {
		fmt.Printf("Error getting installed libraries: %v\n", err)
		return
	}

	for libName, libVersion := range libs {
		fmt.Printf("Library found in project %s: %s (%s)\n", projectName, libName, libVersion)
	}

	// analyze each one and update if possible
	for libName, libVersion := range libs {
		new, age, latest, sha, err := analyze.AnalyzeNPMPackage(libName)
		if err != nil {
			fmt.Printf("Error analyzing package %s: %v\n", libName, err)
			continue
		}

		fmt.Println("\n=== Analyzing file changes between versions:", libVersion, "(current installed) ->", latest, "===")
		// File change analysis with the instaled version and the latest version
		_, err = analyze.AnalyzeNewFiles(libName, libVersion, latest, sha)
		if err != nil {
			fmt.Printf("Warning: Error analyzing new files: %v\n", err)
		}

		if new {
			fmt.Printf("\nWarning: Library %s not old enough to be considered secure to update.\n", libName) // less than 24h
			continue
		} else if age < time.Duration(delay)*time.Hour {
			fmt.Printf("\nWarning: Library %s is very recent (age: %d hours), consider waiting before updating. The minimum delay for this project is %d hours.\n", libName, int(age.Round(time.Hour).Hours()), delay)
			continue
		} else {

			fmt.Println("\nYou want to proceed with the update? [y/n]")
			var response string
			fmt.Scanln(&response)

			if response != "y" {
				fmt.Println("Update cancelled.")
				return
			}

			fmt.Printf("\nUpdating library: %s\n", libName)

			cmd1 := []string{"mkdir", "-p", "/workspace"}
			_, errOut1, err1 := docker.ExecInContainer(container_id, cmd1)
			if err1 != nil {
				fmt.Printf("Error creating workspace directory: %v, stderr: %s\n", err1, errOut1)
				return
			}

			var update_cmd string
			if allowScripts {
				update_cmd = "cd /workspace && npm update " + libName
			} else {
				update_cmd = "cd /workspace && npm update --ignore-scripts " + libName
			}

			cmd := []string{"sh", "-c", update_cmd}

			out, errOut, err := docker.ExecInContainer(container_id, cmd)
			if err != nil {
				fmt.Printf("Error updating library %s: %v, stderr: %s\n", libName, err, errOut)
				continue
			}
			fmt.Printf("Output updating library %s: %s\n", libName, out)
		}
	}
}
