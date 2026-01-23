package ebutil

import (
	"fmt"
	"strings"

	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
)

type InvalidRepoURLError struct {
	repoURL string
	inner   error
}

func (e *InvalidRepoURLError) Error() string {
	return fmt.Sprintf("invalid repository URL %q, please see https://github.com/coder/envbuilder/blob/main/docs/git-auth.md for supported formats: %v", e.repoURL, e.inner)
}

type ParsedURL struct {
	Protocol  string
	User      string
	Password  string
	Host      string
	Port      int
	Path      string
	Reference string
}

// ParseRepoURL parses the given repository URL into its components.
// We used to use chainguard-dev/git-urls for this, but its behaviour
// diverges from the go-git URL parser. To ensure consistency, we now
// use go-git directly.
func ParseRepoURL(repoURL string) (*ParsedURL, error) {
	// Trim #reference from path
	var reference string
	if idx := strings.Index(repoURL, "#"); idx > -1 {
		reference = repoURL[idx+1:]
		repoURL = repoURL[:idx]
	}
	parsed, err := gittransport.NewEndpoint(repoURL)
	if err != nil {
		return nil, &InvalidRepoURLError{repoURL: repoURL, inner: err}
	}
	return &ParsedURL{
		Protocol:  parsed.Protocol,
		User:      parsed.User,
		Password:  parsed.Password,
		Host:      parsed.Host,
		Port:      parsed.Port,
		Path:      parsed.Path,
		Reference: reference,
	}, nil
}
