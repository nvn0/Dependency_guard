// internal/docker/docker.go
package docker

// This file contains the logic for only creating Docker containers for secure development environments with the best configs.

import (
	"Dependency_guard/internal/security"
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	client "github.com/moby/moby/client"
)

// getDockerfileForType returns the path to the appropriate Dockerfile based on the environment type.
func getDockerfileForType(envType string) (string, error) {
	projectRoot, err := getProjectRoot()
	if err != nil {
		return "", err
	}
	fmt.Println("Project root:", projectRoot)

	dockerfileName := ""
	switch envType {
	case "node":
		dockerfileName = "custom_image_node.dockerfile"
	case "node-alpine":
		dockerfileName = "custom_image_node_alpine.dockerfile"
	case "python":
		dockerfileName = "custom_image_python.dockerfile"
	case "go":
		dockerfileName = "custom_image_go.dockerfile"
	default:
		dockerfileName = "custom_image_default.dockerfile"
	}

	return filepath.Join(projectRoot, "internal", "docker", "dockerfiles", dockerfileName), nil
}

// getImageNameForType returns the image name for tagging
func getImageNameForType(envType string) string {
	switch envType {
	case "node":
		return "dependency-guard:node-custom"
	case "node-alpine":
		return "dependency-guard:node-alpine-custom"
	case "python":
		return "dependency-guard:python-custom"
	case "go":
		return "dependency-guard:go-custom"
	default:
		return "dependency-guard:custom"
	}
}

func getProjectRoot() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not get executable path: %v", err)
	}

	// Resolver symlink se existir
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		realPath = exePath // Se não conseguir resolver, usar o path como está
	}

	return filepath.Dir(realPath), nil
}

// createTarStream cria um tar stream do diretório para o build context
func createTarStream(sourceDir string) (io.Reader, error) {
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		tw := tar.NewWriter(pw)
		defer tw.Close()

		// Walk through all files in the directory
		err := filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Get relative path for the tar header
			relPath, err := filepath.Rel(sourceDir, path)
			if err != nil {
				return err
			}

			// Create tar header
			header, err := tar.FileInfoHeader(info, relPath)
			if err != nil {
				return err
			}
			header.Name = relPath

			if err := tw.WriteHeader(header); err != nil {
				return err
			}

			// If file, write content
			if !info.IsDir() {
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				defer file.Close()

				if _, err := io.Copy(tw, file); err != nil {
					return err
				}
			}

			return nil
		})

		if err != nil {
			pw.CloseWithError(err)
		}
	}()

	return pr, nil
}

// buildImage builds a Docker image from the specified Dockerfile
func buildImage(cli *client.Client, dockerfilePath, imageName string) error {
	fmt.Printf("Building image: %s from %s\n", imageName, dockerfilePath)

	// Get the directory containing the Dockerfile (build context)
	buildContextPath := filepath.Dir(dockerfilePath)

	// Create tar stream from the build context directory
	tarStream, err := createTarStream(buildContextPath)
	if err != nil {
		fmt.Printf("\nError creating tar stream: %v\n", err)
		return fmt.Errorf("failed to create tar stream: %v", err)
	}

	response, err := cli.ImageBuild(context.Background(), tarStream, client.ImageBuildOptions{
		Dockerfile: filepath.Base(dockerfilePath),
		Tags:       []string{imageName},
	})
	if err != nil {
		fmt.Printf("\nError building image: %v\n", err)
		return fmt.Errorf("failed to build image: %v", err)
	}
	defer response.Body.Close()

	// Consume the response to wait for build to complete
	_, err = io.Copy(io.Discard, response.Body)
	if err != nil {
		return fmt.Errorf("error reading build response: %v", err)
	}

	fmt.Printf("\nImage %s built successfully\n", imageName)
	return nil
}

func CreateContainer(environmentType, projectName string) (string, error) {
	// Validate environment type
	validTypes := map[string]bool{"node": true, "node-alpine": true, "python": true, "go": true}
	if !validTypes[environmentType] {
		fmt.Printf("\nInvalid environment type: %s. Valid options: node, node-alpine, python, go\n", environmentType)
		return "", fmt.Errorf("invalid environment type: %s", environmentType)
	}

	cli, err := client.New(client.FromEnv)
	if err != nil {
		fmt.Printf("\nError creating Docker client: %v\n", err)
		return "", err
	}
	defer cli.Close()

	dockerfilePath, err := getDockerfileForType(environmentType)
	if err != nil {
		fmt.Printf("\nError getting dockerfile path: %v\n", err)
		return "", err
	}
	imageName := getImageNameForType(environmentType)
	var containerName string = projectName

	// Build image from Dockerfile
	err = buildImage(cli, dockerfilePath, imageName)
	if err != nil {
		fmt.Printf("\nError building image: %v\n", err)
		return "", err
	}

	// Get the appropriate AppArmor profile for the environment type
	armorProfile := security.GetAppArmorProfileForEnv(environmentType)

	// Verify and ensure AppArmor profile is loaded BEFORE creating the container
	profileName, err := security.EnsureAppArmorProfileLoaded(armorProfile)
	if err != nil {
		// If custom profile fails, fall back to docker-default
		fmt.Printf("\nFalling back to docker-default AppArmor profile\n")
		profileName = "docker-default"
	}

	// Build SecurityOpt with the appropriate AppArmor profile
	securityOpt := []string{
		"no-new-privileges",
		"apparmor=docker-default",
		//"seccomp=default", // causa erro, usar o default do Docker que já é seguro, ou seja, não especificar seccomp
		//fmt.Sprintf("apparmor=%s", profileName), // or apparmor=docker-default if fallback
	}

	resp, err := cli.ContainerCreate(
		context.Background(),
		client.ContainerCreateOptions{
			Config: &container.Config{
				Image: imageName,
				Cmd:   []string{"sleep", "infinity"},
				Tty:   false,
				//User:  "0:0",
				User: "1001:1001", // resolvido user normal ja funciona
			},
			HostConfig: &container.HostConfig{
				ReadonlyRootfs: false, // deve ser true apenas para produção e apps que não precisam de escrita, para desenvolvimento pode ser false
				CapDrop:        []string{"ALL"},
				NetworkMode:    container.NetworkMode("bridge"),
				SecurityOpt:    securityOpt,
				Tmpfs: map[string]string{
					"/tmp": "size=200m", // tmpfs mount to prevent writing to disk, with a size limit, removed after a stop to prevent data persistence
				},
			},
			NetworkingConfig: &network.NetworkingConfig{},
			Name:             containerName,
		},
	)

	if err != nil {
		fmt.Println("Error creating container", err)
		return "", err
	}

	fmt.Printf("\nContainer created for %s project: %s with ID: %s\n", environmentType, projectName, resp.ID)
	fmt.Printf("\nUsing AppArmor profile: %s\n", profileName)

	return resp.ID, nil

	// Apply iptables rules to isolate network access (only allow localhost/docker bridge)
	//security.CreateIptablesIsolationRules()
}
