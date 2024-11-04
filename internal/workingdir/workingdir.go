package workingdir

import (
	"fmt"
	"path/filepath"
)

const (
	// defaultWorkingDirBase is the default working location for envbuilder.
	// This is a special directory that must not be modified by the user
	// or images. This is intentionally unexported.
	defaultWorkingDirBase = "/.envbuilder"

	// TempDir is a directory inside the build context inside which
	// we place files referenced by MagicDirectives.
	TempDir = ".envbuilder.tmp"
)

var (
	// Default is the default working directory for Envbuilder.
	// This defaults to /.envbuilder. It should only be used when Envbuilder
	// is known to be running as root inside a container.
	Default WorkingDir
	// Directives are directives automatically appended to Dockerfiles
	// when pushing the image. These directives allow the built image to be
	// 're-used'.
	Directives = fmt.Sprintf(`
COPY --chmod=0755 %[1]s/envbuilder %[2]s/bin/envbuilder
COPY --chmod=0644 %[1]s/image %[2]s/image
USER root
WORKDIR /
ENTRYPOINT ["%[2]s/bin/envbuilder"]
`, TempDir, defaultWorkingDirBase)
)

// WorkingDir is a working directory for envbuilder. It
// will also be present in images built by envbuilder.
type WorkingDir struct {
	base string
}

// At returns a WorkingDir rooted at filepath.Join(paths...)
func At(paths ...string) WorkingDir {
	if len(paths) == 0 {
		return WorkingDir{}
	}
	return WorkingDir{base: filepath.Join(paths...)}
}

// Join returns the result of filepath.Join([m.Path, paths...]).
func (m WorkingDir) Join(paths ...string) string {
	return filepath.Join(append([]string{m.Path()}, paths...)...)
}

// String returns the string representation of the WorkingDir.
func (m WorkingDir) Path() string {
	// Instead of the zero value, use defaultWorkingDir.
	if m.base == "" {
		return defaultWorkingDirBase
	}
	return m.base
}

// Built is a file that is created in the workspace
// when envbuilder has already been run. This is used
// to skip building when a container is restarting.
// e.g. docker stop -> docker start
func (m WorkingDir) Built() string {
	return m.Join("built")
}

// Image is a file that is created in the image when
// envbuilder has already been run. This is used to skip
// the destructive initial build step when 'resuming' envbuilder
// from a previously built image.
func (m WorkingDir) Image() string {
	return m.Join("image")
}

// Features is a directory that contains feature files.
func (m WorkingDir) Features() string {
	return m.Join("features")
}
