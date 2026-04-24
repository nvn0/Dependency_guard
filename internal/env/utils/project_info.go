package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type ProjectInfo struct {
	ProjectName     string `json:"project_name"`
	EnvironmentType string `json:"env_type"`
	ContainerName   string `json:"container_name"`
	ContainerID     string `json:"container_id"`
	CreatedAt       string `json:"timestamp"`
}

func GetProjectEnvType(projectName string) (string, error) {

	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	var state_file string = fmt.Sprintf("%s_state.json", projectName)

	//verify safe-env-projects folder exists
	safeEnvProjectsPath := filepath.Join(home, "safe-env-projects")
	if _, err := os.Stat(safeEnvProjectsPath); os.IsNotExist(err) {
		return "", fmt.Errorf("safe-env-projects folder does not exist: %s", safeEnvProjectsPath)
	}

	//verify project folder exists
	projectPath := filepath.Join(home, "safe-env-projects", projectName)
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		return "", fmt.Errorf("Error: Verify project name - project folder does not exist: %s", projectPath)
	}

	path := filepath.Join(home, "safe-env-projects", projectName, state_file)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", fmt.Errorf("state file does not exist: %s", path)
	}

	// Ler ficheiro
	data, err := os.ReadFile(path)
	if err != nil {
		//panic(err)
		return "", fmt.Errorf("could not read state file: %v", err)
	}

	// Variável onde vai ser guardado
	var project ProjectInfo

	// Converter JSON -> struct
	err = json.Unmarshal(data, &project)
	if err != nil {
		return "", fmt.Errorf("could not unmarshal state file: %v", err)
	}

	// Guardar em variáveis normais
	var envType string = project.EnvironmentType

	return envType, nil

}
