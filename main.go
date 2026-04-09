package main

import (
	"fmt"
	"os"

	"Dependence_guard/internal/env"
	"Dependence_guard/internal/env/analyze"
	"Dependence_guard/internal/env/install"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: safe-env [init <env-type> <project-name> | install <project-name> <library-name>]")
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
		if len(os.Args) != 4 {
			fmt.Println("usage: safe-env install <project-name> <library-name>")
			return
		}
		projectName := os.Args[2]
		libraryName := os.Args[3]
		fmt.Println("Installing library:", libraryName, "in project:", projectName)
		install.Run(projectName, libraryName)

	case "analyze":
		if len(os.Args) != 4 {
			fmt.Println("usage: safe-env analyze <project-name> <library-name>")
			return
		}
		projectName := os.Args[2]
		libraryName := os.Args[3]
		fmt.Println("Analyzing library:", libraryName, "in project:", projectName)
		analyze.Run(projectName, libraryName)
	default:
		fmt.Println("unknown command")
	}
}
