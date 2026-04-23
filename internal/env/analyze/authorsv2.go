package analyze

import (
	"fmt"
)

func getString(m map[string]any, key string) (string, bool) {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case string:
			return val, true
		case map[string]any:
			// tenta name/email comuns
			if name, ok := val["name"].(string); ok {
				return name, true
			}
		}
	}
	return "", false
}

func getUser(m map[string]any, key string) (string, string, bool) {
	v, ok := m[key]
	if !ok {
		return "", "", false
	}

	switch val := v.(type) {
	case map[string]any:
		name, _ := val["name"].(string)
		email, _ := val["email"].(string)
		return name, email, true

	case string:
		return val, "", true
	}

	return "", "", false
}

func getTrustedPublisher(pkg map[string]any) string {

	// 1. root level
	if tp, ok := pkg["trustedPublisher"].(map[string]any); ok {
		return fmt.Sprintf("found (root): %v", tp)
	}

	// 2. inside _npmUser
	if npmUser, ok := pkg["_npmUser"].(map[string]any); ok {
		if tp, ok := npmUser["trustedPublisher"].(map[string]any); ok {
			return fmt.Sprintf("found (_npmUser): %v", tp)
		}
	}

	return "not found"
}

func analyzeNpmPackageData(pkgData map[string]any) {

	fmt.Println("\n=== npm metadata analysis ===")

	// AUTHOR
	fmt.Println("\n[Author]")
	if name, email, ok := getUser(pkgData, "author"); ok {
		fmt.Printf("Author: %s <%s>\n", name, email)
	} else {
		fmt.Println("Author: not found")
	}

	// MAINTAINERS
	fmt.Println("\n[Maintainers]")
	if m, ok := pkgData["maintainers"].([]any); ok {
		for _, v := range m {
			if u, ok := v.(map[string]any); ok {
				name, _ := u["name"].(string)
				email, _ := u["email"].(string)
				fmt.Printf("- %s <%s>\n", name, email)
			}
		}
	} else {
		fmt.Println("Maintainers: not found")
	}

	// _npmUser (CRÍTICO no Axios)
	fmt.Println("\n[_npmUser]")
	if name, email, ok := getUser(pkgData, "_npmUser"); ok {
		fmt.Printf("npmUser: %s <%s>\n", name, email)
	} else {
		fmt.Println("_npmUser: not found")
	}

	// trustedPublisher (ROOT ou nested)
	fmt.Println("\n[trustedPublisher]")
	fmt.Println(getTrustedPublisher(pkgData))

	// DIST integrity
	fmt.Println("\n[Integrity]")
	if dist, ok := pkgData["dist"].(map[string]any); ok {
		if integrity, ok := dist["integrity"].(string); ok {
			fmt.Println("integrity:", integrity)
		} else {
			fmt.Println("integrity: not found")
		}

		if shasum, ok := dist["shasum"].(string); ok {
			fmt.Println("shasum:", shasum)
		} else {
			fmt.Println("shasum: not found")
		}
	} else {
		fmt.Println("dist: not found")
	}
}
