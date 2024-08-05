package buildinfo

import (
	"fmt"
	"runtime/debug"
	"sync"

	"golang.org/x/mod/semver"
)

const (
	noVersion       = "v0.0.0"
	develPreRelease = "devel"
)

var (
	buildInfo      *debug.BuildInfo
	buildInfoValid bool
	readBuildInfo  sync.Once

	version     string
	readVersion sync.Once

	// Injected with ldflags at build time
	tag string
)

func revision() (string, bool) {
	return find("vcs.revision")
}

func find(key string) (string, bool) {
	readBuildInfo.Do(func() {
		buildInfo, buildInfoValid = debug.ReadBuildInfo()
	})
	if !buildInfoValid {
		panic("could not read build info")
	}
	for _, setting := range buildInfo.Settings {
		if setting.Key != key {
			continue
		}
		return setting.Value, true
	}
	return "", false
}

// Version returns the semantic version of the build.
// Use golang.org/x/mod/semver to compare versions.
func Version() string {
	readVersion.Do(func() {
		revision, valid := revision()
		if valid {
			revision = "+" + revision[:7]
		}
		if tag == "" {
			// This occurs when the tag hasn't been injected,
			// like when using "go run".
			// <version>-<pre-release>+<revision>
			version = fmt.Sprintf("%s-%s%s", noVersion, develPreRelease, revision)
			return
		}
		version = "v" + tag
		// The tag must be prefixed with "v" otherwise the
		// semver library will return an empty string.
		if semver.Build(version) == "" {
			version += revision
		}
	})
	return version
}
