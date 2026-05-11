package docker

import (
	"bytes"
	"os/exec"
	"encoding/json"
	"fmt"
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