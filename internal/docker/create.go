// internal/docker/docker.go
package docker


// This file contains the logic for creating and managing Docker containers for secure development environments.

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// getImageForType returns the appropriate Docker image based on the environment type.
// Debian-based slim images are used to minimize attack surface while still providing necessary tools for development.
func getImageForType(envType string) string {
	switch envType {
	case "node":
		//return "node:20"
		return "node:20-slim"
	case "python":
		//return "python:3.11"
		return "python:3.12-slim"
	case "go":
		return "golang:1.21"
	default:
		return "node:20-slim"
	}
}

func CreateContainer(environmentType, projectName string) {
	// Validate environment type
	validTypes := map[string]bool{"node": true, "python": true, "go": true}
	if !validTypes[environmentType] {
		fmt.Printf("Invalid environment type: %s. Valid options: node, python, go\n", environmentType)
		return
	}

	cli, _ := client.NewClientWithOpts(client.FromEnv)

	image := getImageForType(environmentType)
	containerName := "safe-env-" + projectName

	resp, err := cli.ContainerCreate(
		context.Background(),
		&container.Config{
			Image: image,
			Cmd:   []string{"sleep", "infinity"},
			Tty:   false,
		},
		&container.HostConfig{
			ReadonlyRootfs: true,
			CapDrop:        []string{"ALL"},
			NetworkMode:    "none",
			SecurityOpt: []string{
				"no-new-privileges",
				"seccomp=default.json",
			},
		},
		nil, nil,
		containerName,
	)

	if err != nil {
		panic(err)
	}

	fmt.Printf("Container created for %s project (%s): %s\n", environmentType, projectName, resp.ID)
}
