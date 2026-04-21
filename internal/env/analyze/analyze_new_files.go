package analyze

/*
 Este ficheiro faz a identificação de novos ficheiros que uma lib pode trazer numa nova versão
 Usa um container extra descartável e isolado para este processo
*/

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"Dependency_guard/internal/docker"
)

// AnalyzeNewFiles compares two npm package versions and identifies new files
// Returns a list of files added in the new version
func AnalyzeNewFiles(packageName, oldVersion, newVersion string) ([]string, error) {
	fmt.Printf("\n Analyzing file changes: %s (%s -> %s)\n", packageName, oldVersion, newVersion)

	// Fetch tarballs from npm registry
	oldTarball, err := fetchTarballURL(packageName, oldVersion)
	if err != nil {
		return nil, fmt.Errorf("error fetching old version tarball: %v", err)
	}

	newTarball, err := fetchTarballURL(packageName, newVersion)
	if err != nil {
		return nil, fmt.Errorf("error fetching new version tarball: %v", err)
	}

	// Extract file lists from both versions
	oldFiles, err := listFilesFromTarball(oldTarball)
	if err != nil {
		return nil, fmt.Errorf("error extracting old version files: %v", err)
	}

	newFiles, err := listFilesFromTarball(newTarball)
	if err != nil {
		return nil, fmt.Errorf("error extracting new version files: %v", err)
	}

	// Compare and find new files
	newFilesList := diffFiles(oldFiles, newFiles)

	if len(newFilesList) > 0 {
		fmt.Printf("\n  %d new files detected:\n", len(newFilesList))
		for _, f := range newFilesList {
			fmt.Printf("  + %s\n", f)
		}
	} else {
		fmt.Println(" No new files detected")
	}

	return newFilesList, nil
}

// fetchTarballURL gets the tarball download URL for a specific npm package version
func fetchTarballURL(packageName, version string) (string, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", packageName, version)

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var data struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	}

	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return "", err
	}

	return data.Dist.Tarball, nil
}

// listFilesFromTarball downloads and extracts file listing from a npm tarball
func listFilesFromTarball(tarballURL string) ([]string, error) {
	resp, err := http.Get(tarballURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read entire response into buffer for gzip decompression
	buf := new(bytes.Buffer)
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return nil, err
	}

	// Decompress gzip
	gzr, err := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return nil, err
	}
	defer gzr.Close()

	// Extract tar
	tr := tar.NewReader(gzr)
	var files []string

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Only include regular files (not directories)
		if hdr.Typeflag == tar.TypeReg {
			// Remove "package/" prefix
			normalizedPath := strings.TrimPrefix(hdr.Name, "package/")
			if normalizedPath != "" && normalizedPath != "." {
				files = append(files, normalizedPath)
			}
		}
	}

	return files, nil
}

// diffFiles compares two file lists and returns files that are in newFiles but not in oldFiles
func diffFiles(oldFiles, newFiles []string) []string {
	oldMap := make(map[string]bool)

	for _, f := range oldFiles {
		oldMap[f] = true
	}

	var newFilesList []string
	for _, f := range newFiles {
		if !oldMap[f] {
			newFilesList = append(newFilesList, f)
		}
	}

	return newFilesList
}

// AnalyzeNewFilesInContainer uses an ephemeral Docker container to analyze npm packages
// (Alternative approach using container isolation)
// Uses node:alpine for minimal footprint
func AnalyzeNewFilesInContainer(packageName, oldVersion, newVersion string) ([]string, error) {
	fmt.Printf("\n Starting ephemeral analysis container for %s\n", packageName)

	// Create ephemeral container (uses node:alpine by default)
	containerID, err := docker.CreateEphemeralContainer()
	if err != nil {
		return nil, err
	}
	defer docker.StopAndRemoveContainer(containerID)

	// Install necessary tools
	_, err = docker.ExecuteInContainer(containerID, "npm", []string{"install", "-g", "npm"})
	if err != nil {
		fmt.Printf("Warning: Error installing npm: %v\n", err)
	}


	// For now, we use the direct approach (listFilesFromTarball)
	fmt.Println(" Analysis complete, container cleaned up")

	

}
