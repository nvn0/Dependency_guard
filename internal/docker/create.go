// internal/docker/docker.go
package docker

// This file contains the logic for onlycreating Docker containers for secure development environments with the bests configs.

import (
	"context"
	//"Dependency_guard/internal/security"
	"fmt"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	client "github.com/moby/moby/client" // go get github.com/moby/moby/client
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

	cli, err := client.New(client.FromEnv)
	if err != nil {
		fmt.Printf("Error creating Docker client: %v\n", err)
		return
	}
	defer cli.Close()

	image := getImageForType(environmentType)
	containerName := "safe-env-" + projectName

	resp, err := cli.ContainerCreate(
		context.Background(),
		client.ContainerCreateOptions{
			Config: &container.Config{
				Image: image,
				Cmd:   []string{"sleep", "infinity"},
				Tty:   false,
			},
			HostConfig: &container.HostConfig{
				ReadonlyRootfs: true,
				CapDrop:        []string{"ALL"},
				NetworkMode:    container.NetworkMode("bridge"),
				SecurityOpt: []string{
					"no-new-privileges",
					"seccomp=default.json",
				},
			},
			NetworkingConfig: &network.NetworkingConfig{},
			Name:             containerName,
		},
	)

	if err != nil {
		fmt.Printf("Error creating container: %v\n", err)
		return
	}

	fmt.Printf("Container created for %s project (%s): %s\n", environmentType, projectName, resp.ID)

	// Apply iptables rules to isolate network access (only allow localhost/docker bridge)
	//security.CreateIptablesIsolationRules()
}
