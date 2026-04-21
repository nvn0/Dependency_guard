package analyze

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type NpmVersion struct {
	Version      string            `json:"version"`
	Dependencies map[string]string `json:"dependencies"`
	Scripts      map[string]string `json:"scripts"`
	Repository   interface{}       `json:"repository"`
	Dist         struct {
		Integrity string `json:"integrity"`
		Tarball   string `json:"tarball"`
	} `json:"dist"`
}

type Maintainer struct {
	Name string `json:"name"`
}

type NpmPackage struct {
	Name        string                `json:"name"`
	Versions    map[string]NpmVersion `json:"versions"`
	Time        map[string]string     `json:"time"`
	DistTags    map[string]string     `json:"dist-tags"`
	Maintainers []Maintainer          `json:"maintainers"`
}

func analyzeTime(pkg NpmPackage, version string) {
	t := pkg.Time[version]

	parsed, _ := time.Parse(time.RFC3339, t)
	age := time.Since(parsed)

	fmt.Println(" Published:", t)

	if age < 24*time.Hour {
		fmt.Println(" versão muito recente (possível risco)")
	}
}

func analyzeRepo(v NpmVersion) {
	if v.Repository == nil {
		fmt.Println(" sem repo definido")
		return
	}

	fmt.Println(" Repo:", v.Repository)
}

func analyzeScripts(v NpmVersion) {
	for name := range v.Scripts {
		if strings.Contains(name, "install") {
			fmt.Println(" script suspeito:", name)
		}
	}
}

func analyzeDeps(v NpmVersion) {
	fmt.Println(" Dependencies:")

	for dep := range v.Dependencies {
		fmt.Println(" -", dep)
	}

	if len(v.Dependencies) > 20 {
		fmt.Println(" demasiadas dependências")
	}
}

func analyzeIntegrity(v NpmVersion) {
	fmt.Println(" Integrity:", v.Dist.Integrity)

	if v.Dist.Integrity == "" {
		fmt.Println(" sem hash integrity")
	}
}

func diffDeps(old, new map[string]string) {
	for dep := range new {
		if _, ok := old[dep]; !ok {
			fmt.Println(" new dependency:", dep)
		}
	}
}

func analyzeMaintainers(current, previous []Maintainer) {
	prevMap := make(map[string]bool)

	for _, m := range previous {
		prevMap[m.Name] = true
	}

	for _, m := range current {
		if !prevMap[m.Name] {
			fmt.Println(" new maintainer:", m.Name)
		}
	}
}

func extractGitHubRepo(repo interface{}) (string, string) {
	m, ok := repo.(map[string]interface{})
	if !ok {
		return "", ""
	}

	url, ok := m["url"].(string)
	if !ok {
		return "", ""
	}

	url = strings.TrimSuffix(url, ".git")
	url = strings.Replace(url, "git+", "", 1)

	parts := strings.Split(url, "/")
	if len(parts) < 2 {
		return "", ""
	}

	owner := parts[len(parts)-2]
	name := parts[len(parts)-1]

	return owner, name
}

func checkGitHubTag(owner, repo, version string) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/tags", owner, repo)

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println(" erro GitHub:", err)
		return
	}
	defer resp.Body.Close()

	var tags []struct {
		Name string `json:"name"`
	}

	json.NewDecoder(resp.Body).Decode(&tags)

	found := false
	for _, t := range tags {
		if t.Name == version || t.Name == "v"+version {
			found = true
			break
		}
	}

	if !found {
		fmt.Println(" versão não existe como tag no Git:", version)
	}
}

func analyzeGitConsistency(v NpmVersion) {
	owner, repo := extractGitHubRepo(v.Repository)

	if owner == "" {
		fmt.Println(" repo inválido ou ausente")
		return
	}

	fmt.Println(" Repo:", owner+"/"+repo)

	checkGitHubTag(owner, repo, v.Version)
}

// getPreviousVersion finds the most recent version before the given version
func getPreviousVersion(versions map[string]NpmVersion, currentVersion string) string {
	var previousVersion string
	var previousTime string

	for version := range versions {
		if version != currentVersion {
			// Just get the first different version found (simple approach)
			if previousVersion == "" {
				previousVersion = version
			}
			// Could implement semver comparison here for better logic
		}
	}

	_ = previousTime // For future use if implementing time-based comparison
	return previousVersion
}

func AnalyzePackage(pkg string) error {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", pkg)

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var data NpmPackage
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	latest := data.DistTags["latest"]
	version := data.Versions[latest]

	fmt.Println(" Package:", data.Name)
	fmt.Println(" Latest version:", latest)

	analyzeTime(data, latest)
	analyzeRepo(version)
	analyzeScripts(version)
	analyzeDeps(version)
	analyzeIntegrity(version)
	analyzeMaintainers(data.Maintainers, []Maintainer{})
	analyzeGitConsistency(version)

	// Analyze new files compared to previous version
	previousVersion := getPreviousVersion(data.Versions, latest)
	if previousVersion != "" {
		_, err := AnalyzeNewFiles(pkg, previousVersion, latest)
		if err != nil {
			fmt.Printf("Warning: Error analyzing new files: %v\n", err)
		}
	} else {
		fmt.Println("No previous version found for file comparison")
	}

	return nil
}

func Run(projectName, libraryName string) {
	// Placeholder for actual analysis logic
	// In a real implementation, this would involve checking the library against known vulnerabilities,
	// analyzing its dependencies, and providing a risk assessment.

	fmt.Println("Analyzing library:", libraryName, "in project:", projectName)
	err := AnalyzePackage(libraryName)
	if err != nil {
		fmt.Printf("Error analyzing package: %v\n", err)
	}
}
