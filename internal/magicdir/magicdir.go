package magicdir

import (
	"fmt"
	"path/filepath"
)

const (
	// defaultMagicDirBase is the default working location for envbuilder.
	// This is a special directory that must not be modified by the user
	// or images. This is intentionally unexported.
	defaultMagicDirBase = "/.envbuilder"

	// TempDir is a directory inside the build context inside which
	// we place files referenced by MagicDirectives.
	TempDir = ".envbuilder.tmp"
)

var (
	// Default is the default working directory for Envbuilder.
	// This defaults to /.envbuilder. It should only be used when Envbuilder
	// is known to be running as root inside a container.
	Default MagicDir
	// Directives are directives automatically appended to Dockerfiles
	// when pushing the image. These directives allow the built image to be
	// 're-used'.
	Directives = fmt.Sprintf(`
COPY --chmod=0755 %[1]s/envbuilder %[2]s/bin/envbuilder
COPY --chmod=0644 %[1]s/image %[2]s/image
USER root
WORKDIR /
ENTRYPOINT ["%[2]s/bin/envbuilder"]
`, TempDir, defaultMagicDirBase)
)

// MagicDir is a working directory for envbuilder. It
// will also be present in images built by envbuilder.
type MagicDir struct {
	base string
}

// At returns a MagicDir rooted at filepath.Join(paths...)
func At(paths ...string) MagicDir {
	if len(paths) == 0 {
		return MagicDir{}
	}
	return MagicDir{base: filepath.Join(paths...)}
}

// Join returns the result of filepath.Join([m.Path, paths...]).
func (m MagicDir) Join(paths ...string) string {
	return filepath.Join(append([]string{m.Path()}, paths...)...)
}

// String returns the string representation of the MagicDir.
func (m MagicDir) Path() string {
	// Instead of the zero value, use defaultMagicDir.
	if m.base == "" {
		return defaultMagicDirBase
	}
	return m.base
}

// Built is a file that is created in the workspace
// when envbuilder has already been run. This is used
// to skip building when a container is restarting.
// e.g. docker stop -> docker start
func (m MagicDir) Built() string {
	return m.Join("built")
}

// Image is a file that is created in the image when
// envbuilder has already been run. This is used to skip
// the destructive initial build step when 'resuming' envbuilder
// from a previously built image.
func (m MagicDir) Image() string {
	return m.Join("image")
}

// Features is a directory that contains feature files.
func (m MagicDir) Features() string {
	return m.Join("features")
}
