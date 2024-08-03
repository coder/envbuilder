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

	// MagicDir is where all envbuilder related files are stored.
	// This is a special directory that must not be modified
	// by the user or images.
	MagicDir = "/.envbuilder"
)

var (
	ErrNoFallbackImage = errors.New("no fallback image has been specified")

	// MagicFile is a file that is created in the workspace
	// when envbuilder has already been run. This is used
	// to skip building when a container is restarting.
	// e.g. docker stop -> docker start
	MagicFile = filepath.Join(MagicDir, "built")

	// MagicFile is the location of the build context when
	// using remote build mode.
	MagicRemoteRepoDir = filepath.Join(MagicDir, "repo")

	// MagicBinaryLocation is the expected location of the envbuilder binary
	// inside a builder image.
	MagicBinaryLocation = filepath.Join(MagicDir, "bin", "envbuilder")

	// MagicImage is a file that is created in the image when
	// envbuilder has already been run. This is used to skip
	// the destructive initial build step when 'resuming' envbuilder
	// from a previously built image.
	MagicImage = filepath.Join(MagicDir, "image")

	// MagicTempDir is a directory inside the build context inside which
	// we place files referenced by MagicDirectives.
	MagicTempDir = ".envbuilder.tmp"

	// MagicDirectives are directives automatically appended to Dockerfiles
	// when pushing the image. These directives allow the built image to be
	// 're-used'.
	MagicDirectives = fmt.Sprintf(`
COPY --chmod=0755 %[1]s %[2]s
COPY --chmod=0644 %[3]s %[4]s
USER root
WORKDIR /
ENTRYPOINT [%[2]q]
`,
		".envbuilder.tmp/envbuilder", MagicBinaryLocation,
		".envbuilder.tmp/image", MagicImage,
	)
)
