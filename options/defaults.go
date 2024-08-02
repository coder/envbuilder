package options

import (
	"fmt"
	"strings"

	"github.com/go-git/go-billy/v5/osfs"

	giturls "github.com/chainguard-dev/git-urls"
	"github.com/coder/envbuilder/constants"
	"github.com/coder/envbuilder/internal/chmodfs"
)

// DefaultWorkspaceFolder returns the default workspace folder
// for a given repository URL.
func DefaultWorkspaceFolder(repoURL string) string {
	if repoURL == "" {
		return constants.EmptyWorkspaceDir
	}
	parsed, err := giturls.Parse(repoURL)
	if err != nil {
		return constants.EmptyWorkspaceDir
	}
	name := strings.Split(parsed.Path, "/")
	hasOwnerAndRepo := len(name) >= 2
	if !hasOwnerAndRepo {
		return constants.EmptyWorkspaceDir
	}
	repo := strings.TrimSuffix(name[len(name)-1], ".git")
	return fmt.Sprintf("/workspaces/%s", repo)
}

func (o *Options) SetDefaults() {
	// Temporarily removed these from the default settings to prevent conflicts
	// between current and legacy environment variables that add default values.
	// Once the legacy environment variables are phased out, this can be
	// reinstated to the previous default values.
	if len(o.IgnorePaths) == 0 {
		o.IgnorePaths = []string{
			"/var/run",
			// KinD adds these paths to pods, so ignore them by default.
			"/product_uuid", "/product_name",
		}
	}
	if o.InitScript == "" {
		o.InitScript = "sleep infinity"
	}
	if o.InitCommand == "" {
		o.InitCommand = "/bin/sh"
	}

	if o.Filesystem == nil {
		o.Filesystem = chmodfs.New(osfs.New("/"))
	}
	if o.WorkspaceFolder == "" {
		o.WorkspaceFolder = DefaultWorkspaceFolder(o.GitURL)
	}
	if o.BinaryPath == "" {
		o.BinaryPath = "/.envbuilder/bin/envbuilder"
	}
}
