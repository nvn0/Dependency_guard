package docker

import (
	"Dependency_guard/internal/env/utils"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// Executa um comando dentro de um container Docker
func ExecInContainer(container_id string, command []string) (string, string, error) {
	args := append([]string{"exec", container_id}, command...)

	cmd := exec.Command("docker", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

/*
out, errOut, err := ExecInContainer("meu_container", []string{"echo", "hello"})
	if err != nil {
		fmt.Println("Erro:", err)
		fmt.Println("stderr:", errOut)
		return
	}
*/

func ConnectToContainer(projectName string) error {

	envType, container_id, err := utils.GetProjectInfo(projectName)
	if err != nil {
		return fmt.Errorf("Error getting project container ID: %v", err)
	}

	if envType == "node-alpine" {
		fmt.Println("Connecting to container:", container_id, "with shell: /bin/sh")
		cmd := exec.Command("docker", "exec", "-it", container_id, "/bin/sh")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		return cmd.Run()
	} else {

		// Usar exec.Command diretamente para suportar -it
		cmd := exec.Command("docker", "exec", "-it", container_id, "/bin/bash")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		//cmd.Run()

		return cmd.Run()
	}
}

func GetInstalledNPMLibs(container_id string) (map[string]string, error) {
	out, errOut, err := ExecInContainer(container_id, []string{"sh", "-c", "cd /workspace && npm list --depth=0 --json"})
	if err != nil {
		return nil, fmt.Errorf("Erro: %v, stderr: %s", err, errOut)
	}

	// Processar a saída JSON para extrair os nomes das bibliotecas
	var result struct {
		Dependencies map[string]struct {
			Version    string `json:"version"`
			Resolved   string `json:"resolved"`
			Overridden bool   `json:"overridden"`
		} `json:"dependencies"`
	}

	err = json.Unmarshal([]byte(out), &result)
	if err != nil {
		return nil, fmt.Errorf("Erro ao processar JSON: %v", err)
	}

	libs := make(map[string]string)
	for lib, info := range result.Dependencies {
		libs[lib] = info.Version
	}
	//fmt.Println(libs)

	return libs, nil
}
