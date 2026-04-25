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
