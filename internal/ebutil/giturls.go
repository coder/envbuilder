package ebutil

import (
	"fmt"
	"net/url"
	"strings"

	gittransport "github.com/go-git/go-git/v5/plumbing/transport"
)

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
// use go-git directly with some tweaks.
func ParseRepoURL(repoURL string) (*ParsedURL, error) {
	repoURL = fixupScheme(repoURL, "ssh://")
	repoURL = fixupScheme(repoURL, "git://")
	repoURL = fixupScheme(repoURL, "git+ssh://")
	parsed, err := gittransport.NewEndpoint(repoURL)
	if err != nil {
		return nil, fmt.Errorf("parse repo url %q: %w", repoURL, err)
	}
	// Trim #reference from path
	var reference string
	if len(parsed.Path) > 0 { // annoyingly, strings.Index returns 0 if len(s) == 0
		if idx := strings.Index(parsed.Path, "#"); idx > -1 {
			reference = parsed.Path[idx+1:]
			parsed.Path = parsed.Path[:idx]
		}
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

func fixupScheme(repoURL, scheme string) string {
	// go-git tries to handle protocol:// URLs with url.Parse. This fails
	// in the case of e.g. (ssh|git)://git@host:user/path.git
	if cut, found := strings.CutPrefix(repoURL, scheme); found {
		if _, err := url.Parse(repoURL); err != nil && strings.Contains(err.Error(), "invalid port") {
			return cut
		}
	}
	return repoURL
}
