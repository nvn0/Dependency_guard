package env

/* This file contains the logic for initializing secure development environments based on the
specified type (Node.js, Python, Go).
- Creates well configured docker containers with minimal attack surface.
- Applies apparmor profiles to restrict container capabilities and access.
- Applies seccomp profiles to limit syscalls and prevent escape attempts.
- Activates ebpf-based monitoring to detect and block malicious behavior in real-time.
- Uses read-only root filesystems and drops all capabilities to further harden the environment.
*/

import (
	"Dependency_guard/internal/docker"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config file structs
type Config struct {
	ProjectName string   `json:"project_name"`
	Env_type    string   `json:"env_type"`
	ContainerID string   `json:"container_id"`
	Runtime     Runtime  `json:"runtime"`
	Install     Install  `json:"install"`
	Security    Security `json:"security"`
}

type Runtime struct {
	Network    string     `json:"network"`
	Filesystem Filesystem `json:"filesystem"`
}

type Filesystem struct {
	Deny []string `json:"deny"`
}

type Install struct {
	AllowScripts bool `json:"allow_scripts"`
	DelayHours   int  `json:"delay_hours"`
}

type Security struct {
	Ebpf     bool `json:"ebpf"`
	Apparmor bool `json:"apparmor"`
	Seccomp  bool `json:"seccomp"`
}

//---- End of config file structs -----

// State file struct
type Statefile struct {
	ProjectName   string `json:"project_name"`
	Env_type      string `json:"env_type"`
	ContainerName string `json:"container_name"`
	ContainerID   string `json:"container_id"`
	CreatedAt     string `json:"timestamp"`
	Status        string `json:"status"`
}

// Integrity file struct
type Integrityfile struct {
	ProjectName string `json:"project_name"`
	ContainerID string `json:"container_id"`
	Library     string `json:"fingerprint"`
}

// cria uma pasta dentro da home do utilizador (se não existir)
func ensureDirInHome(dirName string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	path := filepath.Join(home, dirName)

	// MkdirAll já trata do "se não existir"
	err = os.MkdirAll(path, 0755)
	if err != nil {
		return "", err
	}

	return path, nil
}

// criar pasta do projeto dentro da pasta base
func createProjectDir(project_path, projectName string) (string, error) {
	projectPath := filepath.Join(project_path, projectName)
	err := os.MkdirAll(projectPath, 0755)
	if err != nil {
		return "", err
	}
	return projectPath, nil
}

func GenerateConfigFile(folderPath, projectName, environmentType, containerID string) {
	fmt.Printf("Generating config file for %s environment...\n", environmentType)

	cfg := Config{
		ProjectName: projectName,
		Env_type:    environmentType,
		ContainerID: containerID,
		Runtime: Runtime{
			Network: "allow",
			Filesystem: Filesystem{
				Deny: []string{
					"~/.ssh",
					".env",
					"/etc/passwd",
				},
			},
		},
		Install: Install{
			AllowScripts: false,
			DelayHours:   24,
		},
		Security: Security{
			Ebpf:     true,
			Apparmor: true,
			Seccomp:  true,
		},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		panic(err)
	}

	err = os.WriteFile(fmt.Sprintf("%s/config.json", folderPath), data, 0644)
	if err != nil {
		panic(err)
	}

}

func GenerateStateFile(folderPath, projectName, environmentType, containerName, containerID string) {

	state := Statefile{
		ProjectName:   projectName,
		Env_type:      environmentType,
		ContainerName: containerName,
		ContainerID:   containerID,
		Status:        "initialized",
	}

	stateData, _ := json.MarshalIndent(state, "", "  ")
	fmt.Println("State file content:")
	fmt.Println(string(stateData))

	var fileName string = fmt.Sprintf("%s_state.json", projectName)

	file, err := os.Create(fmt.Sprintf("%s/%s", folderPath, fileName))
	if err != nil {
		fmt.Printf("Error creating state file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(state)
}

func GenerateIntegrityFile(folderPath, projectName, containerID string) {

	integrity := Integrityfile{
		ProjectName: projectName,
		ContainerID: containerID,
		Library:     "",
	}

	integrityData, _ := json.MarshalIndent(integrity, "", "  ")
	fmt.Println("Integrity file content:")
	fmt.Println(string(integrityData))

	var fileName string = fmt.Sprintf("%s_integrity.json", projectName)

	file, err := os.Create(fmt.Sprintf("%s/%s", folderPath, fileName))
	if err != nil {
		fmt.Printf("Error creating integrity file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encoder.Encode(integrity)
}

// Cria a pasta de ficheiros do projeto e chama as respetivas funçoes pra criar cada um dos ficheiros de configuracao
func GenerateProjectFiles(project_path, projectName, environmentType, containerName, containerID string) {
	if containerID == "" {
		fmt.Println("Error: Container ID is empty. Cannot generate project files.")
		return
	}

	//Generate state file
	GenerateStateFile(project_path, projectName, environmentType, containerName, containerID)

	//Generate config file
	GenerateConfigFile(project_path, projectName, environmentType, containerID)

	//Generate integrity file (empty for now, to be filled after installation)
	GenerateIntegrityFile(project_path, projectName, containerID)

}

/*
Esta funcao chama outras funcoes para criar o container, gerar os ficheiros de configuracao do
projeto.
Chama a funcoes pra criar a config do apparmor e seccomp, e criar o monitoramento
ebpf (mas nao o liga).
*/
func Init(environmentType, projectName string) {
	id, err := docker.CreateContainer(environmentType, projectName)
	if err != nil {
		panic(err) //erro mostra filsystem e path do projeto, para facilitar debugging, arranjar depois para erro mais generico
		//fmt.Println("Error creating container:", err)
	}

	fmt.Printf("Initialized %s environment for project '%s'\n", environmentType, projectName)

	base_path, err := ensureDirInHome("safe-env-projects")
	if err != nil {
		panic(err)
	}

	fmt.Println("Dir criado em:", base_path)

	project_path, err := createProjectDir(base_path, projectName)
	if err != nil {
		panic(err)
	}

	fmt.Println("Project directory created at:", project_path)

	containerName := "safe-env-" + projectName
	GenerateProjectFiles(project_path, projectName, environmentType, containerName, id)
}
