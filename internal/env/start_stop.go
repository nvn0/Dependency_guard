package env

import (
	"Dependency_guard/internal/docker"
	"Dependency_guard/internal/env/utils"
	"fmt"
)

func Start(projectName string) {
	// Get project environment type from state file
	_, container_id, err := utils.GetProjectInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project container ID: %v\n", err)
		return
	}

	err = docker.StartContainer(container_id)
	if err != nil {
		fmt.Printf("Error starting container: %v\n", err)
		return
	}

	cmd1 := []string{"mkdir", "-p", "/workspace"}
	_, errOut1, err1 := docker.ExecInContainer(container_id, cmd1)
	if err1 != nil {
		fmt.Printf("Error creating workspace directory: %v, stderr: %s\n", err1, errOut1)
		return
	}
}

func Stop(projectName string) {
	// Get project environment type from state file
	_, container_id, err := utils.GetProjectInfo(projectName)
	if err != nil {
		fmt.Printf("Error getting project container ID: %v\n", err)
		return
	}

	err = docker.StopContainer(container_id)
	if err != nil {
		fmt.Printf("Error stopping container: %v\n", err)
		return
	}
}
