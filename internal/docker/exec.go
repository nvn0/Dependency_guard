package docker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"Dependency_guard/internal/env/utils"
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

	_, container_id, err := utils.GetProjectInfo(projectName)
	if err != nil {
		return fmt.Errorf("Error getting project container ID: %v", err)
	}

	_, errOut, err := ExecInContainer(container_id, []string{"docker", "exec", "-it", container_id, "/bin/bash"})
	if err != nil {
		return fmt.Errorf("Erro: %v, stderr: %s", err, errOut)
	}
	return nil
}

func GetInstalledNPMLibs(container_id string) ([]string, error) {
	out, errOut, err := ExecInContainer(container_id, []string{"npm", "list", "--depth=0", "--json"})
	if err != nil {
		return nil, fmt.Errorf("Erro: %v, stderr: %s", err, errOut)
	}

	// Processar a saída JSON para extrair os nomes das bibliotecas
	var result struct {
		Dependencies map[string]interface{} `json:"dependencies"`
	}

	err = json.Unmarshal([]byte(out), &result)
	if err != nil {
		return nil, fmt.Errorf("Erro ao processar JSON: %v", err)
	}

	var libs []string
	for lib := range result.Dependencies {
		libs = append(libs, lib)
	}

	return libs, nil
}
