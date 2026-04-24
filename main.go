package main

import (
	"fmt"
	"os"

	"Dependency_guard/internal/env"
	"Dependency_guard/internal/env/analyze"
	"Dependency_guard/internal/env/install"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: safe-env [init <env-type> <project name> | install <project name> <library name>]")
		fmt.Println("env-type: node, python, go")
		return
	}

	switch os.Args[1] {
	case "init":
		if len(os.Args) != 4 {
			fmt.Println("usage: safe-env init <env-type> <project name>")
			fmt.Println("env-type: node, python, go")
			return
		}
		environmentType := os.Args[2]
		projectName := os.Args[3]
		env.Init(environmentType, projectName)

	case "install":
		if len(os.Args) != 4 {
			fmt.Println("usage: safe-env install <project name> <library name>")
			return
		}
		projectName := os.Args[2]
		libraryName := os.Args[3]
		fmt.Println("Installing library:", libraryName, "in project:", projectName)
		install.Run(projectName, libraryName)

	case "analyze":
		if len(os.Args) != 4 {
			fmt.Println("usage: safe-env analyze <project name> <library name>")
			return
		}
		projectName := os.Args[2]
		libraryName := os.Args[3]
		fmt.Println("Analyzing library:", libraryName, "in project:", projectName)
		analyze.Run(projectName, libraryName)

	case "start":
		fmt.Println("Starting safe environment...")

	case "stop":
		fmt.Println("Stopping safe environment...")

	case "help":
		fmt.Println("usage:")
		fmt.Println(" safe-env init <env-type> <project name>")
		fmt.Println(" safe-env install <project name> <library name>")
		fmt.Println(" safe-env update <project name> <library name>")
		fmt.Println(" safe-env analyze <project name> <library name>")
		fmt.Println(" safe-env <project name> start")
		fmt.Println(" safe-env <project name> stop")
		fmt.Println(" safe-env Lockdown network")
		fmt.Println(" safe-env help")

	default:
		fmt.Println("unknown command")
	}
}
