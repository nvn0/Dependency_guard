package analyze

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"go/parser"
	"go/token"

	"golang.org/x/mod/semver"
)

var suspiciousGoImports = []string{
	"os/exec",
	"net/http",
	"net",
	"syscall",
	"unsafe",
	"plugin",
	"reflect",
	"runtime",
	"archive/zip",
}

type goModuleLatestResponse struct {
	Version string `json:"Version"`
	Time    string `json:"Time"`
}

type goModuleAnalysis struct {
	Module            string
	Version           string
	PublishedAt       time.Time
	FileCount         int
	GoFiles           int
	Dependencies      []string
	SuspiciousImports []string
	NewFiles          int
	RemovedFiles      int
	ModifiedFiles     int
}

func AnalyzeGoPackage(libraryName string) error {
	moduleName := normalizeModulePath(libraryName)
	versions, err := fetchGoModuleVersions(moduleName)
	if err != nil {
		return fmt.Errorf("could not list Go module versions for %q: %w", libraryName, err)
	}
	if len(versions) == 0 {
		return fmt.Errorf("no versions found for module %s", moduleName)
	}

	latest := latestSemverVersion(versions)
	previous := previousSemverVersion(versions, latest)

	fmt.Println("\n======== go module analysis ========")
	fmt.Printf(" Module: %s\n", moduleName)
	fmt.Printf(" Latest version: %s\n", latest)
	if previous != "" {
		fmt.Printf(" Previous version: %s\n", previous)
	} else {
		fmt.Println(" No previous version available for comparison")
	}

	latestSummary, err := analyzeGoModuleVersion(moduleName, latest)
	if err != nil {
		return err
	}

	if previous != "" {
		previousSummary, err := analyzeGoModuleVersion(moduleName, previous)
		if err != nil {
			return err
		}
		compareGoModuleSummaries(previousSummary, latestSummary)
	}

	printGoModuleSummary(latestSummary)
	return nil
}

func analyzeGoModuleVersion(module, version string) (*goModuleAnalysis, error) {
	modContent, err := fetchGoModuleText(module, version, ".mod")
	if err != nil {
		return nil, err
	}

	latestInfo, err := fetchGoModuleLatestInfo(module)
	if err != nil {
		latestInfo = &goModuleLatestResponse{Version: version}
	}

	var publishedAt time.Time
	if latestInfo != nil && latestInfo.Time != "" {
		publishedAt, err = time.Parse(time.RFC3339, latestInfo.Time)
		if err != nil {
			publishedAt = time.Time{}
		}
	}

	files, err := fetchGoModuleFiles(module, version)
	if err != nil {
		return nil, err
	}

	suspiciousImports := []string{}
	for name, content := range files {
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		for _, importPath := range collectSuspiciousImports(content) {
			suspiciousImports = append(suspiciousImports, importPath)
		}
	}

	return &goModuleAnalysis{
		Module:            module,
		Version:           version,
		PublishedAt:       publishedAt,
		FileCount:         len(files),
		GoFiles:           countGoFiles(files),
		Dependencies:      parseGoModDependencies(modContent),
		SuspiciousImports: suspiciousImports,
	}, nil
}

func fetchGoModuleVersions(module string) ([]string, error) {
	candidates := []string{module}
	if module != strings.ToLower(module) {
		candidates = append(candidates, strings.ToLower(module)) // Try lowercase version
	}

	var lastErr error
	for _, candidate := range candidates {
		url := fmt.Sprintf("https://proxy.golang.org/%s/@v/list", candidate)
		resp, err := http.Get(url)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}

			versions := []string{}
			for _, line := range strings.Split(string(body), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				versions = append(versions, line)
			}
			return versions, nil
		}

		if resp.StatusCode == http.StatusNotFound {
			lastErr = fmt.Errorf("version-list request failed for %s with status 404: %s", candidate, url)
			continue
		}
		lastErr = fmt.Errorf("version-list request failed for %s with status %d: %s", candidate, resp.StatusCode, url)
	}

	return nil, lastErr
}

func fetchGoModuleText(module, version, suffix string) (string, error) {
	url := fmt.Sprintf("https://proxy.golang.org/%s/@v/%s%s", module, version, suffix)
	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("module-text request failed for %s@%s: %w", module, version, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("module-text request failed for %s@%s with status %d: %s", module, version, resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("module-text body read failed for %s@%s: %w", module, version, err)
	}

	return string(body), nil
}

func fetchGoModuleLatestInfo(module string) (*goModuleLatestResponse, error) {
	url := fmt.Sprintf("https://proxy.golang.org/%s/@latest", module)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("latest-info request failed for %s: %w", module, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("latest-info request failed for %s with status %d: %s", module, resp.StatusCode, url)
	}

	var info goModuleLatestResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

func fetchGoModuleFiles(module, version string) (map[string]string, error) {
	url := fmt.Sprintf("https://proxy.golang.org/%s/@v/%s.zip", module, version)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("module-zip request failed for %s@%s: %w", module, version, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("module-zip request failed for %s@%s with status %d: %s", module, version, resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}

	files := map[string]string{}
	for _, file := range reader.File {
		if file.FileInfo().IsDir() {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}
		files[file.Name] = string(data)
	}
	return files, nil
}

func latestSemverVersion(versions []string) string {
	valid := []string{}
	for _, version := range versions {
		candidate := normalizeVersion(version)
		if semver.IsValid(candidate) {
			valid = append(valid, version)
		}
	}
	if len(valid) == 0 {
		return versions[0]
	}

	sort.Slice(valid, func(i, j int) bool {
		return semver.Compare(normalizeVersion(valid[i]), normalizeVersion(valid[j])) < 0
	})
	return valid[len(valid)-1]
}

func previousSemverVersion(versions []string, current string) string {
	valid := []string{}
	for _, version := range versions {
		candidate := normalizeVersion(version)
		if semver.IsValid(candidate) && version != current {
			valid = append(valid, version)
		}
	}
	if len(valid) == 0 {
		return ""
	}

	sort.Slice(valid, func(i, j int) bool {
		return semver.Compare(normalizeVersion(valid[i]), normalizeVersion(valid[j])) < 0
	})

	for i := len(valid) - 1; i >= 0; i-- {
		if semver.Compare(normalizeVersion(valid[i]), normalizeVersion(current)) < 0 {
			return valid[i]
		}
	}
	return ""
}

func normalizeVersion(version string) string {
	if strings.HasPrefix(version, "v") {
		return version
	}
	return "v" + version
}

func normalizeModulePath(input string) string {
	cleaned := strings.TrimSpace(input)
	if cleaned == "" {
		return cleaned
	}

	if strings.Contains(cleaned, "@") {
		cleaned = strings.Split(cleaned, "@")[0]
	}

	cleaned = strings.TrimPrefix(cleaned, "go get ")
	cleaned = strings.TrimPrefix(cleaned, "module ")
	cleaned = strings.TrimSuffix(cleaned, "/")

	if strings.HasPrefix(cleaned, "github.com/") || strings.HasPrefix(cleaned, "golang.org/") || strings.HasPrefix(cleaned, "gopkg.in/") || strings.HasPrefix(cleaned, "gitlab.com/") || strings.HasPrefix(cleaned, "bitbucket.org/") {
		return cleaned
	}

	if strings.Count(cleaned, "/") == 1 && !strings.Contains(cleaned, ".") {
		return "github.com/" + cleaned
	}

	return cleaned
}

func parseGoModDependencies(content string) []string {
	deps := []string{}
	inRequire := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if trimmed == "require (" {
			inRequire = true
			continue
		}
		if inRequire && trimmed == ")" {
			inRequire = false
			continue
		}
		if inRequire {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				deps = append(deps, fields[0])
			}
			continue
		}
		if strings.HasPrefix(trimmed, "require ") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				deps = append(deps, fields[1])
			}
		}
	}
	return deps
}

func collectSuspiciousImports(content string) []string {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "module.go", content, 0)
	if err != nil {
		return nil
	}

	imports := []string{}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, "\"")
		if contains(suspiciousGoImports, path) {
			imports = append(imports, path)
		}
	}
	return imports
}

func countGoFiles(files map[string]string) int {
	count := 0
	for name := range files {
		if strings.HasSuffix(name, ".go") {
			count++
		}
	}
	return count
}

func compareGoModuleSummaries(previous, latest *goModuleAnalysis) {
	fmt.Println("\nComparing previous and latest versions")
	fmt.Printf(" Files: %d -> %d\n", previous.FileCount, latest.FileCount)
	fmt.Printf(" Go files: %d -> %d\n", previous.GoFiles, latest.GoFiles)

	prevDeps := make(map[string]bool)
	for _, dep := range previous.Dependencies {
		prevDeps[dep] = true
	}

	for _, dep := range latest.Dependencies {
		if !prevDeps[dep] {
			fmt.Printf(" + new dependency: %s\n", dep)
		}
	}

	if len(latest.SuspiciousImports) > 0 {
		fmt.Printf(" Suspicious imports found: %s\n", strings.Join(latest.SuspiciousImports, ", "))
	}

	if !previous.PublishedAt.IsZero() && !latest.PublishedAt.IsZero() {
		age := latest.PublishedAt.Sub(previous.PublishedAt)
		if age < 0 {
			age = -age
		}
		fmt.Printf(" Published delta: %s\n", age.Round(time.Hour))
	}
}

func printGoModuleSummary(summary *goModuleAnalysis) {
	fmt.Printf(" Version: %s\n", summary.Version)
	fmt.Printf(" Files inspected: %d\n", summary.FileCount)
	fmt.Printf(" Go files: %d\n", summary.GoFiles)
	fmt.Printf(" Dependencies: %s\n", strings.Join(summary.Dependencies, ", "))
	if len(summary.SuspiciousImports) > 0 {
		fmt.Printf(" Suspicious imports: %s\n", strings.Join(summary.SuspiciousImports, ", "))
	} else {
		fmt.Println(" Suspicious imports: none")
	}

	if summary.PublishedAt.IsZero() {
		fmt.Println(" Publication time: unavailable")
		return
	}

	age := time.Since(summary.PublishedAt)
	fmt.Printf(" Published age: %s\n", age.Round(time.Hour))
	if age < 24*time.Hour {
		fmt.Println(" Warning: version is younger than 24h, possible risk")
	}
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}
