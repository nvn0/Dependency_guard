package install

import (
	"fmt"
)

func Update(projectName, libraryName string) {
	fmt.Printf("Updating library: %s in project: %s\n", libraryName, projectName)
}

func UpdateAll(projectName string) {
	fmt.Printf("Updating all libraries in project: %s\n", projectName)
}

