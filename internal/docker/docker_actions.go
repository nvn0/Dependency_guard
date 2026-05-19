package docker

import (
	"fmt"
	"os"
	"os/exec"
	//"context"
	//dockertypes "github.com/docker/docker/api/types/container"
	//client "github.com/docker/docker/client"
)

// ----------- API version ---------------------------

/*
func StartContainer(id string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("erro ao criar cliente Docker: %w", err)
	}
	defer cli.Close()

	err = cli.ContainerStart(context.Background(), id, dockertypes.StartOptions{})
	if err != nil {
		return fmt.Errorf("erro ao ligar container %s: %w", id, err)
	}
	fmt.Printf("Container %s ligado\n", id)
	return nil
}

func StopContainer(id string) error {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return fmt.Errorf("erro ao criar cliente Docker: %w", err)
	}
	defer cli.Close()

	var timeout int = 12
	err = cli.ContainerStop(context.Background(), id, dockertypes.StopOptions{Timeout: &timeout})
	if err != nil {
		return fmt.Errorf("erro ao desligar container %s: %w", id, err)
	}
	fmt.Printf("Container %s desligado\n", id)
	return nil
}
*/

// ------------- shell version -------------------------

func StartContainer(id string) error {
	cmd := exec.Command("docker", "start", id)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("erro ao ligar container %s: %w", id, err)
	}
	//fmt.Printf("Container %s ligado\n", id)
	fmt.Println("Container ligado")
	return nil
}

func StopContainer(id string) error {
	cmd := exec.Command("docker", "stop", id)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("erro ao desligar container %s: %w", id, err)
	}
	//fmt.Printf("Container %s desligado\n", id)
	fmt.Println("Container desligado")
	return nil
}
