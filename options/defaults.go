package options

import (
	"fmt"
	"path"
	"strings"

	"github.com/go-git/go-billy/v5/osfs"

	giturls "github.com/chainguard-dev/git-urls"
	"github.com/coder/envbuilder/internal/chmodfs"
	"github.com/coder/envbuilder/internal/workingdir"
)

// DefaultWorkspaceFolder returns the default workspace folder
// for a given repository URL.
func DefaultWorkspaceFolder(workspacesFolder, repoURL string) string {
	// emptyWorkspaceDir is the path to a workspace that has
	// nothing going on... it's empty!
	emptyWorkspaceDir := workspacesFolder + "/empty"

	if repoURL == "" {
		return emptyWorkspaceDir
	}
	parsed, err := giturls.Parse(repoURL)
	if err != nil {
		return emptyWorkspaceDir
	}
	repo := path.Base(parsed.Path)
	// Giturls parsing never actually fails since ParseLocal never
	// errors and places the entire URL in the Path field. This check
	// ensures it's at least a Unix path containing forwardslash.
	if repo == repoURL || repo == "/" || repo == "." || repo == "" {
		return emptyWorkspaceDir
	}
	repo = strings.TrimSuffix(repo, ".git")
	return fmt.Sprintf("%s/%s", workspacesFolder, repo)
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
	if o.WorkspaceBaseDir == "" {
		o.WorkspaceBaseDir = "/workspaces"
	}
	if o.WorkspaceFolder == "" {
		o.WorkspaceFolder = DefaultWorkspaceFolder(o.WorkspaceBaseDir, o.GitURL)
	}
	if o.BinaryPath == "" {
		o.BinaryPath = "/.envbuilder/bin/envbuilder"
	}
	if o.WorkingDirBase == "" {
		o.WorkingDirBase = workingdir.Default.Path()
	}
}
