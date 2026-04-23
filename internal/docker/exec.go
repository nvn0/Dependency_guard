package docker

import (
	"bytes"
	"os/exec"
)

// Executa um comando dentro de um container Docker
func ExecInContainer(container string, command []string) (string, string, error) {
	args := append([]string{"exec", container}, command...)

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
