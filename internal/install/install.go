// internal/install/install.go
package install

import (
	"fmt"
	"os/exec"
)

func Run(args []string) {
	fmt.Println("Running secure install...")

	cmd := exec.Command("docker", append([]string{
		"exec",
		"safe-env",
	}, args...)...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
	}

	fmt.Println(string(output))
}
