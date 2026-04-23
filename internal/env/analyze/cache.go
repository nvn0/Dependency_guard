package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type VersionCache struct {
	Maintainers []string `json:"maintainers"`
	Timestamp   string   `json:"timestamp"`
}

type LibraryCache map[string]VersionCache

// getLibsCacheDir returns the path to ~/.safe-env-projects/libs_data
func getLibsCacheDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	cacheDir := filepath.Join(homeDir, "safe-env-projects", "libs_data")

	// Create directory if it doesn't exist
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create cache directory: %v", err)
	}

	return cacheDir, nil
}

// getLibraryCachePath returns the path to the cache file for a specific library
func getLibraryCachePath(libName string) (string, error) {
	cacheDir, err := getLibsCacheDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(cacheDir, libName+".json"), nil
}

// LoadLibraryCache loads the cache for a specific library
func LoadLibraryCache(libName string) (LibraryCache, error) {
	cachePath, err := getLibraryCachePath(libName)
	if err != nil {
		return nil, err
	}

	// If file doesn't exist, return empty cache
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		return make(LibraryCache), nil
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache file: %v", err)
	}

	var cache LibraryCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, fmt.Errorf("failed to parse cache file: %v", err)
	}

	return cache, nil
}

// SaveLibraryCache saves the cache for a specific library
func SaveLibraryCache(libName string, cache LibraryCache) error {
	cachePath, err := getLibraryCachePath(libName)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cache: %v", err)
	}

	if err := os.WriteFile(cachePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write cache file: %v", err)
	}

	return nil
}

// UpdateVersionCache adds or updates a version in the cache
func UpdateVersionCache(libName string, version string, maintainers []Maintainer) error {
	cache, err := LoadLibraryCache(libName)
	if err != nil {
		return err
	}

	// Convert Maintainer objects to strings
	maintainerNames := make([]string, len(maintainers))
	for i, m := range maintainers {
		maintainerNames[i] = m.Name
	}

	cache[version] = VersionCache{
		Maintainers: maintainerNames,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}

	return SaveLibraryCache(libName, cache)
}

// GetPreviousVersionMaintainers returns the maintainers from the previous version in cache
func GetPreviousVersionMaintainers(libName, currentVersion string) ([]Maintainer, error) {
	cache, err := LoadLibraryCache(libName)
	if err != nil {
		return nil, err
	}

	// Get the current version entry to find the previous one
	currentEntry, exists := cache[currentVersion]
	if !exists {
		// Current version not in cache, return empty
		return []Maintainer{}, nil
	}

	// Parse current timestamp
	currentTime, err := time.Parse(time.RFC3339, currentEntry.Timestamp)
	if err != nil {
		return []Maintainer{}, nil
	}

	// Find the most recent version before current
	var previousVersion string
	var previousTime time.Time

	for version, entry := range cache {
		if version == currentVersion {
			continue
		}

		versionTime, err := time.Parse(time.RFC3339, entry.Timestamp)
		if err != nil {
			continue
		}

		if versionTime.Before(currentTime) && (previousVersion == "" || versionTime.After(previousTime)) {
			previousVersion = version
			previousTime = versionTime
		}
	}

	if previousVersion == "" {
		return []Maintainer{}, nil
	}

	// Convert stored maintainer names back to Maintainer objects
	prevEntry := cache[previousVersion]
	maintainers := make([]Maintainer, len(prevEntry.Maintainers))
	for i, name := range prevEntry.Maintainers {
		maintainers[i] = Maintainer{Name: name}
	}

	return maintainers, nil
}
