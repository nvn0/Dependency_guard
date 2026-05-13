package env

/*
Este codigo interage com o ficheiro ~/save-env-projects/projects.txt para guardar os nomes dos projetos
criados, verificar se um projeto já existe e listar os projetos guardados. O objetivo é manter um registo
dos projetos criados pelo utilizador.
*/

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	SaveProjectsDir  = "safe-env-projects"
	ProjectsFileName = "projects.txt"
)

// SaveProject appends the project name to the projects list file
func SaveProject(projectName string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	projectsFilePath := filepath.Join(homeDir, SaveProjectsDir, ProjectsFileName)

	// Read existing projects
	var projects []string
	if data, err := os.ReadFile(projectsFilePath); err == nil {
		content := strings.TrimSpace(string(data))
		if content != "" {
			projects = strings.Split(content, "\n")
		}
	}

	// Append the new project name
	projects = append(projects, projectName)

	// Write the updated list back to the file
	content := strings.Join(projects, "\n") + "\n"
	if err := os.WriteFile(projectsFilePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write to file %s: %v", projectsFilePath, err)
	}

	return nil
}

// ProjectExists checks if a project name already exists in the projects list
func ProjectExists(projectName string) (bool, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false, fmt.Errorf("failed to get home directory: %v", err)
	}

	projectsFilePath := filepath.Join(homeDir, SaveProjectsDir, ProjectsFileName)

	data, err := os.ReadFile(projectsFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to read file %s: %v", projectsFilePath, err)
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		return false, nil
	}

	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == projectName {
			return true, nil
		}
	}

	return false, nil
}

// ListSavedProjects prints all saved projects
func ListSavedProjects() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %v", err)
	}

	projectsFilePath := filepath.Join(homeDir, SaveProjectsDir, ProjectsFileName)

	data, err := os.ReadFile(projectsFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No projects saved yet")
			return nil
		}
		return fmt.Errorf("failed to read file %s: %v", projectsFilePath, err)
	}

	content := strings.TrimSpace(string(data))
	if content == "" {
		fmt.Println("No projects saved yet")
		return nil
	}

	fmt.Println("Saved projects:")
	for i, line := range strings.Split(content, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			fmt.Printf("%d. %s\n", i+1, trimmed)
		}
	}

	return nil
}
