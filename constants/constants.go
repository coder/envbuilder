package constants

import (
	"errors"
	"fmt"
	"path/filepath"
)

const (
	// WorkspacesDir is the path to the directory where
	// all workspaces are stored by default.
	WorkspacesDir = "/workspaces"

	// EmptyWorkspaceDir is the path to a workspace that has
	// nothing going on... it's empty!
	EmptyWorkspaceDir = WorkspacesDir + "/empty"

	// defaultMagicDir is the default working location for envbuilder.
	// This is a special directory that must not be modified by the user
	// or images. This is intentionally unexported.
	defaultMagicDir = "/.envbuilder"

	// MagicTempDir is a directory inside the build context inside which
	// we place files referenced by MagicDirectives.
	MagicTempDir = ".envbuilder.tmp"

	// MagicDirectives are directives automatically appended to Dockerfiles
	// when pushing the image. These directives allow the built image to be
	// 're-used'.
	MagicDirectives = `
COPY --chmod=0755 .envbuilder.tmp/envbuilder /.envbuilder/bin/envbuilder
COPY --chmod=0644 .envbuilder.tmp/image /.envbuilder/image
USER root
WORKDIR /
ENTRYPOINT ["/.envbuilder/bin/envbuilder"]
`
)

// ErrNoFallbackImage is returned when no fallback image has been specified.
var ErrNoFallbackImage = errors.New("no fallback image has been specified")

// MagicDir is a working directory for envbuilder. It
// will also be present in images built by envbuilder.
type MagicDir string

// String returns the string representation of the MagicDir.
func (m MagicDir) Path() string {
	if m == "" {
		// Instead of the zero value, use defaultMagicDir.
		return defaultMagicDir
	}
	return filepath.Join("/", string(m))
}

// MagicFile is a file that is created in the workspace
// when envbuilder has already been run. This is used
// to skip building when a container is restarting.
// e.g. docker stop -> docker start
func (m MagicDir) Built() string {
	return filepath.Join(m.Path(), "built")
}

// MagicImage is a file that is created in the image when
// envbuilder has already been run. This is used to skip
// the destructive initial build step when 'resuming' envbuilder
// from a previously built image.
func (m MagicDir) Image() string {
	return filepath.Join(m.Path(), "image")
}
