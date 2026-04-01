package main

import (
	"fmt"
	"os"

	"Dependency_guard/internal/env"
	"Dependency_guard/internal/install"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: safe-env [init <env-type> <project-name> | install <library-name>]")
		fmt.Println("env-type: node, python, go")
		return
	}

	switch os.Args[1] {
	case "init":
		if len(os.Args) != 4 {
			fmt.Println("usage: safe-env init <env-type> <project-name>")
			fmt.Println("env-type: node, python, go")
			return
		}
		environmentType := os.Args[2]
		projectName := os.Args[3]
		env.Init(environmentType, projectName)
	case "install":
		if len(os.Args) < 3 {
			fmt.Println("usage: safe-env install <library-name>")
			return
		}
		install.Run(os.Args[2:])
	default:
		fmt.Println("unknown command")
	}
}
