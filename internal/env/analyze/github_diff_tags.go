package analyze

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type Commit struct {
	Author struct {
		Login string `json:"login"`
	} `json:"author"`
	Committer struct {
		Login string `json:"login"`
	} `json:"committer"`
}

type CompareResponse struct {
	Commits []Commit `json:"commits"`
}

func extractUsers(commits []Commit) map[string]bool {
	users := make(map[string]bool)

	for _, c := range commits {
		if c.Author.Login != "" {
			users[c.Author.Login] = true
		}
		if c.Committer.Login != "" {
			users[c.Committer.Login] = true
		}
	}
	return users
}

func getCompare(owner, repo, base, head string) ([]Commit, error) {
	url := fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/compare/%s...%s",
		owner, repo, base, head,
	)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var data CompareResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return data.Commits, nil
}

// imprime novos contributors
func PrintNewGithubContributors(owner, repo, v1, v2 string) error {
	//fmt.Println("Owner:", owner, "Repo:", repo, "Version 1:", v1, "Version 2:", v2)

	if owner == "" || repo == "" {
		return fmt.Errorf("repositório GitHub inválido ou ausente")
	}

	// contributors antes de v1 (baseline)
	beforeCommits, err := getCompare(owner, repo, "", "v"+v1)
	if err != nil {
		return err
	}

	// contributors entre v1 e v2
	rangeCommits, err := getCompare(owner, repo, "v"+v1, "v"+v2)
	if err != nil {
		return err
	}

	beforeUsers := extractUsers(beforeCommits)
	rangeUsers := extractUsers(rangeCommits)

	if len(rangeCommits) > 0 {
		last := rangeCommits[len(rangeCommits)-1]

		author := last.Author.Login
		if author == "" {
			author = last.Committer.Login
		}

		fmt.Println("\n=== Autor do último commit ===")
		if author != "" {
			fmt.Println(author)
		} else {
			fmt.Println("Desconhecido")
		}
	}

	fmt.Println("\n=== New Github Contributors ===")

	var found bool = false
	for user := range rangeUsers {
		if !beforeUsers[user] {
			fmt.Println("-", user)
			found = true
		}
	}

	if !found {
		fmt.Println("Nenhum contributor novo encontrado.")
	}

	return nil
}
