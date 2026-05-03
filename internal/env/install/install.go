// internal/env/install/install.go
package install

import (
	"fmt"
	"os/exec"
)

func InstallLib(projectName, libraryName string) {
	fmt.Println("Running secure install...")

	cmd := exec.Command("docker", append([]string{
		"exec",
		"safe-env",
	}, "npm", "install", libraryName)...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
	}

	fmt.Println(string(output))
}
