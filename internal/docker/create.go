// internal/docker/docker.go
package docker

// This file contains the logic for onlycreating Docker containers for secure development environments with the bests configs.

import (
	"Dependency_guard/internal/security"
	"context"
	"fmt"
	"io"

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

// pullImage pulls the Docker image from registry if it doesn't exist locally
func pullImage(cli *client.Client, imageName string) error {
	fmt.Printf("Pulling image: %s\n", imageName)

	response, err := cli.ImagePull(context.Background(), imageName, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %v", imageName, err)
	}
	defer response.Close()

	// Consume the response to wait for pull to complete
	_, err = io.Copy(io.Discard, response)
	if err != nil {
		return fmt.Errorf("error reading pull response: %v", err)
	}

	fmt.Printf("Image %s pulled successfully\n", imageName)
	return nil
}

func CreateContainer(environmentType, projectName string) (string, error) {
	// Validate environment type
	validTypes := map[string]bool{"node": true, "python": true, "go": true}
	if !validTypes[environmentType] {
		fmt.Printf("Invalid environment type: %s. Valid options: node, python, go\n", environmentType)
		return "", fmt.Errorf("invalid environment type: %s", environmentType)
	}

	cli, err := client.New(client.FromEnv)
	if err != nil {
		fmt.Printf("Error creating Docker client: %v\n", err)
		return "", err
	}
	defer cli.Close()

	image := getImageForType(environmentType)
	containerName := "safe-env-" + projectName

	// Pull image if it doesn't exist locally
	err = pullImage(cli, image)
	if err != nil {
		fmt.Printf("Error pulling image: %v\n", err)
		return "", err
	}

	// Get the appropriate AppArmor profile for the environment type
	armorProfile := security.GetAppArmorProfileForEnv(environmentType)

	// Verify and ensure AppArmor profile is loaded BEFORE creating the container
	profileName, err := security.EnsureAppArmorProfileLoaded(armorProfile)
	if err != nil {
		// If custom profile fails, fall back to docker-default
		fmt.Printf("Falling back to docker-default AppArmor profile\n")
		profileName = "docker-default"
	}

	// Build SecurityOpt with the appropriate AppArmor profile
	securityOpt := []string{
		"no-new-privileges",
		"seccomp=default.json",
		fmt.Sprintf("apparmor=%s", profileName), // or apparmor=docker-default if fallback
	}

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
				SecurityOpt:    securityOpt,
			},
			NetworkingConfig: &network.NetworkingConfig{},
			Name:             containerName,
		},
	)

	if err != nil {
		fmt.Println("Error creating container", err)
		return "", err
	}

	fmt.Printf("Container created for %s project: %s with ID: %s\n", environmentType, projectName, resp.ID)
	fmt.Printf("Using AppArmor profile: %s\n", profileName)

	return resp.ID, nil

	// Apply iptables rules to isolate network access (only allow localhost/docker bridge)
	//security.CreateIptablesIsolationRules()
}
