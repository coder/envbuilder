package options

import (
	"fmt"
	"strings"

	"github.com/go-git/go-billy/v5/osfs"

	giturls "github.com/chainguard-dev/git-urls"
	"github.com/coder/envbuilder/internal/chmodfs"
	"github.com/coder/envbuilder/internal/magicdir"
)

// EmptyWorkspaceDir is the path to a workspace that has
// nothing going on... it's empty!
var EmptyWorkspaceDir = "/workspaces/empty"

// DefaultWorkspaceFolder returns the default workspace folder
// for a given repository URL.
func DefaultWorkspaceFolder(repoURL string) string {
	if repoURL == "" {
		return EmptyWorkspaceDir
	}
	parsed, err := giturls.Parse(repoURL)
	if err != nil {
		return EmptyWorkspaceDir
	}
	name := strings.Split(parsed.Path, "/")
	hasOwnerAndRepo := len(name) >= 2
	if !hasOwnerAndRepo {
		return EmptyWorkspaceDir
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
	if o.RemoteRepoDir == "" {
		o.RemoteRepoDir = magicdir.Default.Join("repo")
	}
	if o.BinaryPath == "" {
		o.BinaryPath = "/.envbuilder/bin/envbuilder"
	}
	if o.MagicDirBase == "" {
		o.MagicDirBase = magicdir.Default.Path()
	}
}
