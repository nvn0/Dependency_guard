package main

import (
	"flag"
	"fmt"
	"os"
	"Dependency_guard/internal/docker"
	"Dependency_guard/internal/env"
	"Dependency_guard/internal/env/analyze"
	"Dependency_guard/internal/env/install"
	"Dependency_guard/internal/env/update"
	"Dependency_guard/internal/security"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: safe-env [init <env-type> <project name> | install <project name> <library name>]")
		fmt.Println("env-type: node, python, go")
		return
	}

	switch os.Args[1] {
	case "init":
		initFlags := flag.NewFlagSet("init", flag.ContinueOnError)
		useDefaultAppArmor := initFlags.Bool("daa", false, "use the default Docker AppArmor profile")
		useRootUser := initFlags.Bool("root", false, "run the container as root")

		if err := initFlags.Parse(os.Args[2:]); err != nil {
			return
		}
		if initFlags.NArg() != 2 {
			fmt.Println("usage: safe-env init [--daa] [--root] <env-type> <project name>")
			fmt.Println("env-type: node, node-alpine, python, go")
			return
		}
		environmentType := initFlags.Arg(0)
		projectName := initFlags.Arg(1)
		env.Init(environmentType, projectName, *useDefaultAppArmor, *useRootUser)

	case "install":
		if len(os.Args) != 4 {
			fmt.Println("usage: safe-env install <project name> <library name>")
			return
		}
		projectName := os.Args[2]
		libraryName := os.Args[3]
		fmt.Println("Installing library:", libraryName, "in project:", projectName)
		install.InstallLib(projectName, libraryName)

	case "update":
		if len(os.Args) != 4 {
			fmt.Println("usage: safe-env update <project name> <library name>")
			return
		}
		if os.Args[3] == "all" {
			projectName := os.Args[2]
			//fmt.Println("Updating all libraries in project:", projectName)
			update.UpdateAll(projectName)
			return
		}

		projectName := os.Args[2]
		libraryName := os.Args[3]
		//fmt.Println("Updating library:", libraryName, "in project:", projectName)
		update.Update(projectName, libraryName)

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
		if len(os.Args) != 3 {
			fmt.Println("usage: safe-env start <project name>")
			return
		}

		projectName := os.Args[2]
		fmt.Println("Starting safe environment for project:", projectName)
		fmt.Print("ID: ")
		env.Start(projectName)

	case "stop":
		if len(os.Args) != 3 {
			fmt.Println("usage: safe-env stop <project name>")
			return
		}
		projectName := os.Args[2]
		fmt.Println("Stopping safe environment for project:", projectName)
		fmt.Print("ID: ")
		env.Stop(projectName)

	case "lockdown":
		if os.Args[2] != "network" {
			fmt.Println("usage: safe-env lockdown network")
			return
		}

		/*
			// solução provisória
			// não dá pra executar auto pq é preciso sudo, e depois é o sudo nao reconhece o caminho do ~/.local/bin/safe-env
			// era preciso criar um link simbólico em /usr/local/bin

			fmt.Println("Run:")
			fmt.Println("sudo iptables -I DOCKER-USER -i docker0 -j DROP")

			fmt.Println("To deactivate, run:")
			fmt.Println("sudo iptables -D DOCKER-USER -i docker0 -j DROP")

			fmt.Println("\nOr to delete all rules:")
			fmt.Println("sudo iptables -F DOCKER-USER")
		*/

		if len(os.Args) != 4 {
			fmt.Println("usage: sudo safe-env lockdown network <on/off>")
			return
		}
		if os.Args[3] == "on" {
			fmt.Println("Locking down network...")
			security.BlockAllNetworkAccess()

		} else if os.Args[3] == "off" {
			fmt.Println("Allowing network access...")
			security.RemoveIptablesRules()

		} else {
			fmt.Println("usage: sudo safe-env lockdown network <on/off>")
			return
		}

	case "list":
		if err := env.ListSavedProjects(); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	case "show":
		if len(os.Args) != 4 {
			fmt.Println("usage: safe-env show <project name> packages")
			return
		}
		if os.Args[3] != "packages" {
			fmt.Println("usage: safe-env show <project name> packages")
			return
		}
		projectName := os.Args[2]

		update.ShowInstalledLibs(projectName)

	case "connect":
		if len(os.Args) != 3 {
			fmt.Println("usage: safe-env connect <project name>")
			return
		}
		projectName := os.Args[2]
		fmt.Println("Connecting to safe environment for project:", projectName)
		err := docker.ConnectToContainer(projectName)
		if err != nil {
			fmt.Printf("Error connecting to container: %v\n", err)
			return
		}

	case "monitor":
		if len(os.Args) != 3 {
			fmt.Println("usage: sudo safe-env monitor <project name>")
			return
		}
		projectName := os.Args[2]
		env.Monitor(projectName)

	case "enforce":
		if len(os.Args) != 3 {
			fmt.Println("usage: sudo safe-env enforce <project name>")
			return
		}
		projectName := os.Args[2]
		env.Enforce(projectName)

	case "help":
		fmt.Println("usage:")
		fmt.Println(" safe-env init [--daa] [--root] <env-type> <project name>")
		fmt.Println(" safe-env install <project name> <library name>")
		fmt.Println(" safe-env update <project name> <library name>")
		fmt.Println(" safe-env update <project name> all")
		fmt.Println(" safe-env analyze <project name> <library name>")
		fmt.Println(" safe-env show <project name> packages")
		fmt.Println(" safe-env start <project name>")
		fmt.Println(" safe-env stop <project name>")
		fmt.Println(" sudo safe-env lockdown network <on/off>")
		fmt.Println(" safe-env connect <project name>")
		fmt.Println(" sudo safe-env monitor <project name>")
		fmt.Println(" sudo safe-env enforce <project name>")
		fmt.Println(" safe-env list")
		fmt.Println(" safe-env help")

	default:
		fmt.Println("unknown command - try 'safe-env help' for usage")
	}
}
