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
	"Dependency_guard/internal/security"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Config file struct - Mutable runtime configuration
type Config struct {
	Install Install `json:"install"`
	Network bool    `json:"network"`
	EBPF    EBPF    `json:"ebpf"`
}

type Install struct {
	AllowScripts bool `json:"allow_scripts"`
	DelayHours   int  `json:"delay_hours"`
}

type EBPF struct {
	Enabled   bool     `json:"enabled"`
	Whitelist []string `json:"whitelist"`
	DenyPaths []string `json:"deny_paths"`
}

//---- End of config file structs -----

// State file struct - Immutable state and security info
type Statefile struct {
	ProjectName   string            `json:"project_name"`
	Env_type      string            `json:"env_type"`
	ContainerName string            `json:"container_name"`
	ContainerID   string            `json:"container_id"`
	CreatedAt     string            `json:"timestamp"`
	Status        string            `json:"status"`
	SecurityFixed SecurityImmutable `json:"security_immutable"`
}

type SecurityImmutable struct {
	AppArmorProfile     string   `json:"apparmor_profile"`
	AppArmorPath        string   `json:"apparmor_path"`
	SeccompEnabled      bool     `json:"seccomp_enabled"`
	ReadonlyFilesystem  bool     `json:"readonly_filesystem"`
	CapabilitiesDropped []string `json:"capabilities_dropped"`
}

// Integrity file struct
type Integrityfile struct {
	ProjectName string   `json:"project_name"`
	ContainerID string   `json:"container_id"`
	Libraries   []string `json:"libraries"`
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

func GenerateConfigFile(folderPath, projectName string) {
	fmt.Printf("\nGenerating config file for %s...\n", projectName)

	cfg := Config{
		Install: Install{
			AllowScripts: false,
			DelayHours:   24,
		},
		Network: true,
		EBPF: EBPF{
			Enabled: true,
			Whitelist: []string{
				"npm.npmjs.com",
				"registry.npmjs.org",
			},
			DenyPaths: []string{
				"~/.ssh",
				".env",
				"/etc/passwd",
				"/etc/shadow",
			},
		},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		panic(err)
	}

	fileName := fmt.Sprintf("%s/%s_config.json", folderPath, projectName)
	err = os.WriteFile(fileName, data, 0644)
	if err != nil {
		panic(err)
	}

}

func GenerateStateFile(folderPath, projectName, environmentType, containerName, containerID, appArmorProfile, appArmorPath string) {

	state := Statefile{
		ProjectName:   projectName,
		Env_type:      environmentType,
		ContainerName: containerName,
		ContainerID:   containerID,
		CreatedAt:     time.Now().Format("15:04:05 02/01/2006"), //European date format
		Status:        "initialized",
		SecurityFixed: SecurityImmutable{
			AppArmorProfile:     appArmorProfile,
			AppArmorPath:        appArmorPath,
			SeccompEnabled:      true,
			ReadonlyFilesystem:  true,
			CapabilitiesDropped: []string{"ALL"},
		},
	}

	stateData, _ := json.MarshalIndent(state, "", "  ")
	fmt.Println("\nState file content:")
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
		Libraries:   []string{},
	}

	integrityData, _ := json.MarshalIndent(integrity, "", "  ")
	fmt.Println("\nIntegrity file content:")
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
func GenerateProjectFiles(project_path, projectName, environmentType, containerName, containerID, appArmorProfile, appArmorPath string) {
	if containerID == "" {
		fmt.Println("Error: Container ID is empty. Cannot generate project files.")
		return
	}

	//Generate state file (immutable security info)
	GenerateStateFile(project_path, projectName, environmentType, containerName, containerID, appArmorProfile, appArmorPath)

	//Generate config file (mutable runtime configuration)
	GenerateConfigFile(project_path, projectName)

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

	exists, err := ProjectExists(projectName)
	if err != nil {
		fmt.Printf("Error checking if project name is already in use: %v\n", err)
		return
	}
	if exists {
		fmt.Printf("Project '%s' already exists. Choose another name.\n", projectName)
		return
	}

	id, err := docker.CreateContainer(environmentType, projectName)
	if err != nil {
		panic(err) //erro mostra filsystem e path do projeto, para facilitar debugging, arranjar depois para erro mais generico
		//fmt.Println("Error creating container:", err)
	}

	fmt.Printf("\nInitialized %s environment for project '%s'\n", environmentType, projectName)

	base_path, err := ensureDirInHome("safe-env-projects")
	if err != nil {
		panic(err)
	}

	fmt.Println("\nDir criado em:", base_path)

	project_path, err := createProjectDir(base_path, projectName)
	if err != nil {
		panic(err)
	}

	fmt.Println("\nProject directory created at:", project_path)

	//containerName := "safe-env-" + projectName
	var containerName string = projectName

	// Get AppArmor profile info
	armorProfile := security.GetAppArmorProfileForEnv(environmentType)

	GenerateProjectFiles(project_path, projectName, environmentType, containerName, id, armorProfile.Name, armorProfile.InstalledPath)

	// Save project name to ~/safe-env-projects/projects.txt
	if err := SaveProject(projectName); err != nil {
		fmt.Printf("Warning: Failed to save project name: %v\n", err)
	}
}
