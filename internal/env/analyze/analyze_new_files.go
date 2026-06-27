package analyze

/*
 Este ficheiro faz a identificação de novos ficheiros que uma lib pode trazer numa nova versão
 Usa um container extra descartável e isolado para este processo
*/

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	//"Dependency_guard/internal/docker"
)

var suspiciousExt = map[string]bool{
	".py":   true,
	".vbs":  true,
	".bat":  true,
	".exe":  true,
	".ps1":  true,
	".sh":   true,
	".mond": true,
	".cmd":  true,
}

// CalculateTarballSHA512Integrity calcula o hash SHA512 do tarball inteiro
// e retorna no formato npm: "sha512-<base64>"
func CalculateTarballSHA512Integrity(tarballURL string) (string, error) {
	resp, err := http.Get(tarballURL)
	if err != nil {
		return "", fmt.Errorf("erro ao fazer download do tarball: %w", err)
	}
	defer resp.Body.Close()

	hash := sha512.New()

	// Ler todos os bytes do tarball e calcular hash
	_, err = io.Copy(hash, resp.Body)
	if err != nil {
		return "", fmt.Errorf("erro ao ler tarball: %w", err)
	}

	// Digest (64 bytes)
	digest := hash.Sum(nil)

	// Codificar em Base64
	base64Hash := base64.StdEncoding.EncodeToString(digest)

	// Prefixar com "sha512-"
	return "sha512-" + base64Hash, nil
}

// AnalyzeNewFiles compares two npm package versions and identifies new files
// Returns a list of files added in the new version
func AnalyzeNewFiles(packageName, oldVersion, newVersion, remote_sha512Hash string) ([]string, error) {
	fmt.Printf("\nAnalyzing file changes: %s (%s -> %s)\n", packageName, oldVersion, newVersion)

	// Fetch tarballs from npm registry
	oldTarball, err := fetchTarballURL(packageName, oldVersion)
	if err != nil {
		return nil, fmt.Errorf("error fetching old version tarball: %v", err)
	}

	newTarball, err := fetchTarballURL(packageName, newVersion)
	if err != nil {
		return nil, fmt.Errorf("error fetching new version tarball: %v", err)
	}

	local_sha512Hash, err := CalculateTarballSHA512Integrity(newTarball)
	if err != nil {
		return nil, fmt.Errorf("error calculating local SHA512 hash: %v", err)
	}

	if local_sha512Hash != remote_sha512Hash {
		fmt.Printf("\n"+Red+"Warning: SHA512 hash mismatch for %s@%s\n"+Reset, packageName, newVersion)
		fmt.Printf("Local SHA512:  %s\n", local_sha512Hash)
		fmt.Printf("Remote SHA512: %s\n", remote_sha512Hash)
	} else {
		fmt.Printf("\n"+Green+"Tarball SHA512 hash verified for %s@%s\n"+Reset, packageName, newVersion)
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
		fmt.Printf("\n "+Yellow+"%d new files detected:"+Reset+"\n", len(newFilesList))
		for _, f := range newFilesList {
			fmt.Printf("  + %s\n", f)

			ext := strings.ToLower(filepath.Ext(f))

			if suspiciousExt[ext] {
				fmt.Printf("\033[1;31m   [!] WARNING: suspicious file extension detected:\033[0m %s\n", ext)
			}
		}
	} else {
		fmt.Println(Green + "\n No new files detected" + Reset)
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
// Nao é feito um download real do tarball para o disco, é feito tudo em memória para eficiência, lido  como network stream
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
