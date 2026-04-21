package docker

// This file manages ephemeral Docker containers for analyzing npm package changes
// Used to isolate and compare tarball contents between versions

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/moby/moby/api/types/container"
	client "github.com/moby/moby/client"
)

// AnalyzeContainerConfig defines the configuration for an ephemeral analysis container
type AnalyzeContainerConfig struct {
	Image      string
	Entrypoint []string
	Labels     map[string]string
}

// CreateEphemeralContainer creates a temporary container for npm package analysis
// Uses node:alpine for minimal footprint
// Returns the container ID for reference
func CreateEphemeralContainer() (string, error) {
	return CreateEphemeralAnalyzeContainer("node:alpine")
}

// CreateEphemeralAnalyzeContainer creates a temporary container for npm package analysis
// Returns the container ID for reference
// Parameters:
//   - image: Docker image to use (e.g., "node:alpine", "node:20-slim")
func CreateEphemeralAnalyzeContainer(image string) (string, error) {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		fmt.Printf("Error creating Docker client: %v\n", err)
		return "", err
	}
	defer cli.Close()

	// Pull image if needed
	err = pullImage(cli, image)
	if err != nil {
		fmt.Printf("Error pulling image: %v\n", err)
		return "", err
	}

	containerName := fmt.Sprintf("analyze-ephemeral-%d", time.Now().Unix())

	config := &container.Config{
		Image: image,
		Cmd:   []string{"sleep", "3600"}, // 1 hour timeout
		Tty:   false,
		Labels: map[string]string{
			"type":    "ephemeral-analysis",
			"app":     "dependency-guard",
			"auto_rm": "true",
		},
	}

	hostConfig := &container.HostConfig{
		AutoRemove:     true,
		CapDrop:        []string{"ALL"},
		ReadonlyRootfs: false, // Precisa escrever ficheiros temporários
		Tmpfs: map[string]string{
			"/tmp": "size=100m,mode=1777",
		},
	}

	resp, err := cli.ContainerCreate(
		context.Background(),
		config,
		hostConfig,
		nil,
		nil,
		containerName,
	)

	if err != nil {
		fmt.Println("Error creating ephemeral container:", err)
		return "", err
	}

	// Start the container
	_, err = cli.ContainerStart(context.Background(), resp.ID, container.StartOptions{})
	if err != nil {
		fmt.Println("Error starting ephemeral container:", err)
		return "", err
	}

	fmt.Printf("✓ Ephemeral analysis container created: %s\n", resp.ID[:12])
	return resp.ID, nil
}

// ExecuteInContainer runs a command inside the ephemeral container
func ExecuteInContainer(containerID, command string, args []string) (string, error) {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return "", err
	}
	defer cli.Close()

	cmd := append([]string{command}, args...)

	resp, err := cli.ContainerExecCreate(context.Background(), containerID, container.ExecOptions{
		Cmd:          cmd,
		AttachStdout: true,
		AttachStderr: true,
	})

	if err != nil {
		return "", err
	}

	execResp, err := cli.ContainerExecAttach(context.Background(), resp.ID, container.ExecStartOptions{})
	if err != nil {
		return "", err
	}
	defer execResp.Close()

	output, err := io.ReadAll(execResp.Reader)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

// StopAndRemoveContainer stops and removes the ephemeral container
func StopAndRemoveContainer(containerID string) error {
	cli, err := client.New(client.FromEnv)
	if err != nil {
		return err
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Stop the container
	_, err = cli.ContainerStop(ctx, containerID, container.StopOptions{})
	if err != nil {
		fmt.Printf("Warning: Error stopping container: %v\n", err)
		// Continue to remove anyway
	}

	// Remove the container
	_, err = cli.ContainerRemove(context.Background(), containerID, container.RemoveOptions{
		Force: true,
	})

	if err != nil {
		fmt.Printf("Error removing container: %v\n", err)
		return err
	}

	fmt.Printf("✓ Ephemeral container removed: %s\n", containerID[:12])
	return nil
}
