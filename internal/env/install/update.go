package install

import (
	"Dependency_guard/internal/env/analyze"
	"fmt"
)

func Update(projectName, libraryName string) {
	fmt.Printf("Updating library: %s in project: %s\n", libraryName, projectName)

	fmt.Println("Running a scan on lib:", libraryName)
	new, err := analyze.AnalyzePackage(libraryName)
	if err != nil {
		fmt.Printf("Error analyzing package: %v\n", err)
		return
	}

	if new {
		fmt.Printf("\nWarning: Library %s not old enough to be considered secure to update.\n", libraryName)
		return
	} else {
		fmt.Printf("\nUpdating library: %s\n", libraryName)
	}
}

func UpdateAll(projectName string) {
	fmt.Printf("Updating all libraries in project: %s\n", projectName)

	//get installed libs

	// analyze each one and update if possible

}
