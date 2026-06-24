package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// GetHomeDir returns the home directory, detecting if running with sudo
func GetHomeDir() (string, error) {
	// Check if running with sudo
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser != "" {
		return filepath.Join("/home", sudoUser), nil
	}

	// Otherwise use the current user's home directory
	return os.UserHomeDir()
}

func GetProjectInfo(projectName string) (string, string, error) {

	home, err := GetHomeDir()
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

func GetContainerIP(containerID string) (string, error) {
	// Execute: docker inspect <containerID> | grep IPAddress
	cmd := exec.Command("sh", "-c", fmt.Sprintf("docker inspect %s | grep '\"IPAddress\"'", containerID))
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("could not get container IP: %v", err)
	}

	// Parse output: "IPAddress": "172.17.0.2",
	line := strings.TrimSpace(string(output))
	parts := strings.Split(line, "\"")
	if len(parts) < 4 {
		return "", fmt.Errorf("could not parse IP address from: %s", line)
	}

	ip := parts[3]
	if ip == "" {
		return "", fmt.Errorf("empty IP address")
	}

	return ip, nil
}

// GetContainerPID gets the PID of a Docker container using docker inspect
func GetContainerPID(containerID string) (string, error) {
	// Executar: docker inspect -f '{{.State.Pid}}' <containerID>
	cmd := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", containerID)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("could not get container PID: %v", err)
	}

	// Parse output and trim whitespace
	pid := strings.TrimSpace(string(output))
	if pid == "" || pid == "0" {
		return "", fmt.Errorf("container %s is not running or has no PID", containerID)
	}

	return pid, nil
}

func GetConfigInfo(projectName string) (ConfigInfo, error) {

	home, err := GetHomeDir()
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
