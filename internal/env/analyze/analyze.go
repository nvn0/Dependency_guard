package analyze

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"
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

type NpmVersionCheck struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Author      NpmUser   `json:"author"`
	Maintainers []NpmUser `json:"maintainers"`
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

type NpmUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func analyzeTime(pkg NpmPackage, version string) {
	t := pkg.Time[version]

	parsed, _ := time.Parse(time.RFC3339, t)
	age := time.Since(parsed)

	fmt.Println(" Published:", t)

	if age < 24*time.Hour {
		fmt.Println(" versão muito recente (24h <) (possível risco)")
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
		fmt.Println(" no hash integrity")
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

func analyzeGitConsistency(v NpmVersion) (string, string) {
	owner, repo := extractGitHubRepo(v.Repository)

	if owner == "" {
		fmt.Println(" repo inválido ou ausente")
		return "", ""
	}

	fmt.Println(" Repo:", owner+"/"+repo)

	checkGitHubTag(owner, repo, v.Version)

	return owner, repo
}

// getPreviousVersion finds the immediate previous version before the given version using semver
func getPreviousVersion(pkg NpmPackage, currentVersion string) string {
	// Collect all valid semantic versions
	var versions []string

	for version := range pkg.Time {
		// Skip non-version entries
		if version == "created" || version == "modified" || version == currentVersion {
			continue
		}

		// Add 'v' prefix if not present for semver.IsValid
		versionWithV := version
		if !strings.HasPrefix(version, "v") {
			versionWithV = "v" + version
		}

		// Only include valid semantic versions
		if semver.IsValid(versionWithV) {
			versions = append(versions, version)
		}
	}

	if len(versions) == 0 {
		return ""
	}

	// Sort versions by semver in ascending order
	sort.Slice(versions, func(i, j int) bool {
		viWithV := "v" + versions[i]
		vjWithV := "v" + versions[j]
		return semver.Compare(viWithV, vjWithV) < 0
	})

	// Find current version in sorted list and return the one before it
	currentWithV := currentVersion
	if !strings.HasPrefix(currentVersion, "v") {
		currentWithV = "v" + currentVersion
	}

	for i := len(versions) - 1; i >= 0; i-- {
		vWithV := "v" + versions[i]
		if semver.Compare(vWithV, currentWithV) < 0 {
			return versions[i]
		}
	}

	return ""
}

func fetchVersion(pkg, version string) (*NpmVersionCheck, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", pkg, version)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data NpmVersionCheck
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}

	return &data, nil
}

func compareUsers(a, b NpmUser) bool {
	return a.Email == b.Email && a.Name == b.Name
}

func analyzeLastVersionAuthors(pkg, previous, latest string) {
	latestData, err := fetchVersion(pkg, latest)
	if err != nil {
		fmt.Println("Error fetching latest:", err)
		return
	}

	prevData, err := fetchVersion(pkg, previous)
	if err != nil {
		fmt.Println("Error fetching previous:", err)
		return
	}

	fmt.Println("\n=== npm integrity analysis ===")

	// Comparação publisher / author
	fmt.Println("\n[Author]")
	if !compareUsers(prevData.Author, latestData.Author) {
		fmt.Println("Warning: Author changed!")
		fmt.Printf("Previous: %s <%s> | Latest: %s <%s>\n",
			prevData.Author.Name, prevData.Author.Email,
			latestData.Author.Name, latestData.Author.Email)
	} else {
		fmt.Println("Author: ", latestData.Author.Name, "-", latestData.Author.Email)
		fmt.Println("OK")
	}

	// Comparação maintainers (básica)
	fmt.Println("\n[Maintainers count]")
	if len(prevData.Maintainers) != len(latestData.Maintainers) {
		fmt.Println("Warning: Maintainers changed!")
		fmt.Printf("Previous: %d | Latest: %d\n", len(prevData.Maintainers), len(latestData.Maintainers))
	} else {
		fmt.Println("OK")
	}

	// Version sanity check
	//fmt.Println("\n[Version]")
	//fmt.Printf("Prev: %s | Latest: %s\n", previous, latest)

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

	owner, repo := analyzeGitConsistency(version)

	// Get maintainers from cache for previous version comparison
	previousMaintainers, err := GetPreviousVersionMaintainers(pkg, latest)
	if err != nil {
		fmt.Println("\nWarning: Could not load maintainer cache: ", err)
		previousMaintainers = []Maintainer{}
	}

	analyzeMaintainers(data.Maintainers, previousMaintainers)

	// Update cache with current version
	if err := UpdateVersionCache(pkg, latest, data.Maintainers); err != nil {
		fmt.Printf("Warning: Could not save maintainer cache: %v\n", err)
	}

	// Analyze new files compared to previous version
	previousVersion := getPreviousVersion(data, latest)
	if previousVersion != "" {

		err = PrintNewGithubContributors(owner, repo, previousVersion, latest)
		if err != nil {
			fmt.Println("Erro:", err)
		}

		analyzeLastVersionAuthors(pkg, previousVersion, latest)

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

	err := AnalyzePackage(libraryName)
	if err != nil {
		fmt.Printf("Error analyzing package: %v\n", err)
	}
}
