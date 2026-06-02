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

type ConfigInfo struct {
	Install struct {
		AllowScripts bool `json:"allow_scripts"`
		Delay        int  `json:"delay_hours"`
	} `json:"install"`
	Network bool `json:"network"`
	Ebpf    struct {
		Enabled   bool     `json:"enabled"`
		Whitelist []string `json:"whitelist"`
		DenyPaths []string `json:"deny_paths"`
	} `json:"ebpf"`
}

func GetProjectInfo(projectName string) (string, string, error) {

	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}

	var state_file string = fmt.Sprintf("%s_state.json", projectName)

	//verify safe-env-projects folder exists
	safeEnvProjectsPath := filepath.Join(home, "safe-env-projects")
	if _, err := os.Stat(safeEnvProjectsPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("safe-env-projects folder does not exist: %s", safeEnvProjectsPath)
	}

	//verify project folder exists
	projectPath := filepath.Join(home, "safe-env-projects", projectName)
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("Error: Verify project name - project folder does not exist: %s", projectPath)
	}

	path := filepath.Join(home, "safe-env-projects", projectName, state_file)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", "", fmt.Errorf("state file does not exist: %s", path)
	}

	// Ler ficheiro
	data, err := os.ReadFile(path)
	if err != nil {
		//panic(err)
		return "", "", fmt.Errorf("could not read state file: %v", err)
	}

	// Variável onde vai ser guardado
	var project ProjectInfo

	// Converter JSON -> struct
	err = json.Unmarshal(data, &project)
	if err != nil {
		return "", "", fmt.Errorf("could not unmarshal state file: %v", err)
	}

	// Guardar em variáveis normais
	var envType string = project.EnvironmentType
	var containerID string = project.ContainerID

	return envType, containerID, nil
}

func GetConfigInfo(projectName string) (ConfigInfo, error) {

	home, err := os.UserHomeDir()
	if err != nil {
		return ConfigInfo{}, err
	}

	var config_file string = fmt.Sprintf("%s_config.json", projectName)

	//verify safe-env-projects folder exists
	safeEnvProjectsPath := filepath.Join(home, "safe-env-projects")
	if _, err := os.Stat(safeEnvProjectsPath); os.IsNotExist(err) {
		return ConfigInfo{}, fmt.Errorf("safe-env-projects folder does not exist: %s", safeEnvProjectsPath)
	}

	//verify project folder exists
	projectPath := filepath.Join(home, "safe-env-projects", projectName)
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		return ConfigInfo{}, fmt.Errorf("Error: Verify project name - project folder does not exist: %s", projectPath)
	}

	path := filepath.Join(home, "safe-env-projects", projectName, config_file)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ConfigInfo{}, fmt.Errorf("config file does not exist: %s", path)
	}

	// Ler ficheiro
	data, err := os.ReadFile(path)
	if err != nil {
		//panic(err)
		return ConfigInfo{}, fmt.Errorf("could not read config file: %v", err)
	}

	// Variável onde vai ser guardado
	var config ConfigInfo

	//debug
	//fmt.Printf("Config file content:\n%s\n", string(data))

	// Debug: Parse como map genérico para ver a estrutura real
	/*
		var rawData map[string]interface{}
		err = json.Unmarshal(data, &rawData)
		if err != nil {
			return ConfigInfo{}, fmt.Errorf("could not unmarshal as map: %v", err)
		}
		fmt.Printf("Raw JSON structure: %+v\n", rawData)
		for key, value := range rawData {
			fmt.Printf("  Key: '%s', Value: %v (type: %T)\n", key, value, value)
		}
	*/

	// Converter JSON -> struct
	err = json.Unmarshal(data, &config)
	if err != nil {
		return ConfigInfo{}, fmt.Errorf("could not unmarshal config file: %v", err)
	}

	//debug
	//fmt.Printf("Parsed Config: %+v\n", config)

	return config, nil

}
