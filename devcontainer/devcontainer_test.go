package devcontainer_test

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coder/envbuilder/devcontainer"
	"github.com/coder/envbuilder/devcontainer/features"
	"github.com/coder/envbuilder/testutil/registrytest"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

const workingDir = "/.envbuilder"

var emptyRemoteOpts []remote.Option

func stubLookupEnv(string) (string, bool) {
	return "", false
}

func TestParse(t *testing.T) {
	t.Parallel()
	raw := `{
  "build": {
    "dockerfile": "Dockerfile",
    "context": ".",
  },
  // Comments here!
  "image": "codercom/code-server:latest"
}`
	parsed, err := devcontainer.Parse([]byte(raw))
	require.NoError(t, err)
	require.Equal(t, "Dockerfile", parsed.Build.Dockerfile)
}

func TestCompileWithFeatures(t *testing.T) {
	t.Parallel()
	registry := registrytest.New(t)
	featureOne := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/one:tomato", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:          "rust",
			Version:     "tomato",
			Name:        "Rust",
			Description: "Example description!",
			ContainerEnv: map[string]string{
				"TOMATO": "example",
			},
		},
	})
	featureTwo := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/two:potato", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:          "go",
			Version:     "potato",
			Name:        "Go",
			Description: "Example description!",
			ContainerEnv: map[string]string{
				"POTATO": "example",
			},
			Options: map[string]features.Option{
				"version": {
					Type: "string",
				},
			},
		},
	})

	raw := `{
  "build": {
    "dockerfile": "Dockerfile",
    "context": ".",
  },
  // Comments here!
  "image": "localhost:5000/envbuilder-test-codercom-code-server:latest",
  "features": {
	"` + featureOne + `": {},
	"` + featureTwo + `": "potato"
  }
}`
	dc, err := devcontainer.Parse([]byte(raw))
	require.NoError(t, err)
	fs := memfs.New()

	featureOneMD5 := md5.Sum([]byte(featureOne))
	featureOneName := fmt.Sprintf("one-%x", featureOneMD5[:4])
	featureOneDir := "/.envbuilder/features/" + featureOneName
	featureTwoMD5 := md5.Sum([]byte(featureTwo))
	featureTwoName := fmt.Sprintf("two-%x", featureTwoMD5[:4])
	featureTwoDir := "/.envbuilder/features/" + featureTwoName

	t.Run("WithoutBuildContexts", func(t *testing.T) {
		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		require.Equal(t, `FROM localhost:5000/envbuilder-test-codercom-code-server:latest

USER root
# Rust tomato - Example description!
WORKDIR `+featureOneDir+`
ENV TOMATO=example
RUN _CONTAINER_USER="1000" _REMOTE_USER="1000" ./install.sh
# Go potato - Example description!
WORKDIR `+featureTwoDir+`
ENV POTATO=example
RUN VERSION="potato" _CONTAINER_USER="1000" _REMOTE_USER="1000" ./install.sh
USER 1000`, params.DockerfileContent)
	})

	t.Run("WithBuildContexts", func(t *testing.T) {
		params, err := dc.Compile(fs, "", workingDir, "", "", true, stubLookupEnv)
		require.NoError(t, err)

		registryHost := strings.TrimPrefix(registry, "http://")

		require.Equal(t, `FROM scratch AS envbuilder_feature_`+featureOneName+`
COPY --from=`+registryHost+`/coder/one / /

FROM scratch AS envbuilder_feature_`+featureTwoName+`
COPY --from=`+registryHost+`/coder/two / /

FROM localhost:5000/envbuilder-test-codercom-code-server:latest

USER root
# Rust tomato - Example description!
WORKDIR /.envbuilder/features/`+featureOneName+`
ENV TOMATO=example
RUN --mount=type=bind,from=envbuilder_feature_`+featureOneName+`,target=/.envbuilder/features/`+featureOneName+`,rw _CONTAINER_USER="1000" _REMOTE_USER="1000" ./install.sh
# Go potato - Example description!
WORKDIR /.envbuilder/features/`+featureTwoName+`
ENV POTATO=example
RUN --mount=type=bind,from=envbuilder_feature_`+featureTwoName+`,target=/.envbuilder/features/`+featureTwoName+`,rw VERSION="potato" _CONTAINER_USER="1000" _REMOTE_USER="1000" ./install.sh
USER 1000`, params.DockerfileContent)

		require.Equal(t, map[string]string{
			registryHost + "/coder/one": featureOneDir,
			registryHost + "/coder/two": featureTwoDir,
		}, params.FeatureContexts)
	})
}

func TestCompileWithFeaturesOverrideInstallOrder(t *testing.T) {
	t.Parallel()
	registry := registrytest.New(t)
	featureOne := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/one:tomato", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "one",
			Version: "tomato",
			Name:    "One",
		},
	})
	featureTwo := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/two:potato", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "two",
			Version: "potato",
			Name:    "Two",
		},
	})
	featureThree := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/three:apple", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "three",
			Version: "apple",
			Name:    "Three",
		},
	})

	featureOneMD5 := md5.Sum([]byte(featureOne))
	featureOneDir := fmt.Sprintf("/.envbuilder/features/one-%x", featureOneMD5[:4])
	featureTwoMD5 := md5.Sum([]byte(featureTwo))
	featureTwoDir := fmt.Sprintf("/.envbuilder/features/two-%x", featureTwoMD5[:4])
	featureThreeMD5 := md5.Sum([]byte(featureThree))
	featureThreeDir := fmt.Sprintf("/.envbuilder/features/three-%x", featureThreeMD5[:4])

	t.Run("OverrideReverseOrder", func(t *testing.T) {
		// featureThree then featureTwo are explicitly ordered first; featureOne
		// is unconstrained and falls to the alphabetical remainder.
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureOne + `": {},
    "` + featureTwo + `": {},
    "` + featureThree + `": {}
  },
  "overrideFeatureInstallOrder": ["` + featureThree + `", "` + featureTwo + `"]
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		// featureThree and featureTwo come first (in override order),
		// then featureOne last (alphabetical remainder).
		require.Contains(t, params.DockerfileContent, "WORKDIR "+featureThreeDir+"\n")
		require.Contains(t, params.DockerfileContent, "WORKDIR "+featureTwoDir+"\n")
		require.Contains(t, params.DockerfileContent, "WORKDIR "+featureOneDir+"\n")

		threeIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureThreeDir)
		twoIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureTwoDir)
		oneIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureOneDir)
		require.Less(t, threeIdx, twoIdx, "three should be installed before two")
		require.Less(t, twoIdx, oneIdx, "two should be installed before one")
	})

	t.Run("UnknownOverrideEntryIgnored", func(t *testing.T) {
		// An entry in overrideFeatureInstallOrder that doesn't match any
		// feature key should be silently ignored.
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureOne + `": {},
    "` + featureTwo + `": {}
  },
  "overrideFeatureInstallOrder": ["does-not-exist", "` + featureTwo + `"]
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		twoIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureTwoDir)
		oneIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureOneDir)
		require.Less(t, twoIdx, oneIdx, "two should be installed before one")
	})
}

func TestCompileWithFeaturesInstallsAfter(t *testing.T) {
	t.Parallel()
	registry := registrytest.New(t)

	// featureBase has no deps.
	featureBase := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/base:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "base",
			Version: "1.0.0",
			Name:    "Base",
		},
	})
	// featureTop declares installsAfter: ["base"], so it must come after featureBase.
	featureTop := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/top:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:            "top",
			Version:       "1.0.0",
			Name:          "Top",
			InstallsAfter: []string{"base"},
		},
	})
	baseRef, err := name.ParseReference(featureBase)
	require.NoError(t, err)
	baseCanonical := baseRef.Context().Name()
	featureTopByRef := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/top-by-ref:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:            "top-by-ref",
			Version:       "1.0.0",
			Name:          "TopByRef",
			InstallsAfter: []string{baseCanonical},
		},
	})

	featureBaseMD5 := md5.Sum([]byte(featureBase))
	featureBaseDir := fmt.Sprintf("/.envbuilder/features/base-%x", featureBaseMD5[:4])
	featureTopMD5 := md5.Sum([]byte(featureTop))
	featureTopDir := fmt.Sprintf("/.envbuilder/features/top-%x", featureTopMD5[:4])
	featureTopByRefMD5 := md5.Sum([]byte(featureTopByRef))
	featureTopByRefDir := fmt.Sprintf("/.envbuilder/features/top-by-ref-%x", featureTopByRefMD5[:4])

	t.Run("InstallsAfterRespected", func(t *testing.T) {
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureTop + `": {},
    "` + featureBase + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		baseIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureBaseDir)
		topIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureTopDir)
		require.Greater(t, baseIdx, -1, "base feature should be present")
		require.Greater(t, topIdx, -1, "top feature should be present")
		require.Less(t, baseIdx, topIdx, "base should be installed before top (installsAfter)")
	})

	t.Run("InstallsAfterAbsentDepIgnored", func(t *testing.T) {
		// featureTop declares installsAfter: ["base"], but base is not in features.
		// This is a soft dep — should succeed with just featureTop.
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureTop + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		_, err = dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err, "absent installsAfter dep should not cause an error")
	})

	t.Run("OverrideWinsOverInstallsAfter", func(t *testing.T) {
		// overrideFeatureInstallOrder forces top before base, contradicting
		// top's installsAfter declaration. Override takes precedence.
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureTop + `": {},
    "` + featureBase + `": {}
  },
  "overrideFeatureInstallOrder": ["` + featureTop + `", "` + featureBase + `"]
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		topIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureTopDir)
		baseIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureBaseDir)
		require.Greater(t, topIdx, -1, "top feature should be present")
		require.Greater(t, baseIdx, -1, "base feature should be present")
		require.Less(t, topIdx, baseIdx, "override should force top before base")
	})

	t.Run("InstallsAfterCanonicalRefRespected", func(t *testing.T) {
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureTopByRef + `": {},
    "` + featureBase + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		baseIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureBaseDir)
		topIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureTopByRefDir)
		require.Greater(t, baseIdx, -1, "base feature should be present")
		require.Greater(t, topIdx, -1, "top-by-ref feature should be present")
		require.Less(t, baseIdx, topIdx, "base should be installed before top-by-ref (installsAfter by canonical ref)")
	})
}

func TestCompileWithFeaturesDependsOn(t *testing.T) {
	t.Parallel()
	registry := registrytest.New(t)

	featureA := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/a:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "a",
			Version: "1.0.0",
			Name:    "A",
		},
	})
	// featureB hard-depends on featureA. The dependsOn key uses the full OCI
	// reference of featureA so that auto-add (DependsOnAutoAdded) can fetch it
	// from the registry when it is not explicitly declared in features.
	featureB := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/b:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:        "b",
			Version:   "1.0.0",
			Name:      "B",
			DependsOn: map[string]map[string]any{featureA: {}},
		},
	})
	featureEarly := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/aaa-early:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:        "early",
			Version:   "1.0.0",
			Name:      "Early",
			DependsOn: map[string]map[string]any{"late": {}},
		},
	})
	featureLate := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/zzz-late:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "late",
			Version: "1.0.0",
			Name:    "Late",
		},
	})
	lateRef, err := name.ParseReference(featureLate)
	require.NoError(t, err)
	lateCanonical := lateRef.Context().Name()
	featureByRef := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/by-ref:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:        "by-ref",
			Version:   "1.0.0",
			Name:      "ByRef",
			DependsOn: map[string]map[string]any{lateCanonical: {}},
		},
	})
	featureLateV1 := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/zzz-late:1.0.0", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "late-v1",
			Version: "1.0.0",
			Name:    "LateV1",
		},
	})
	featureLateV2 := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/zzz-late:2.0.0", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "late-v2",
			Version: "2.0.0",
			Name:    "LateV2",
		},
	})

	featureEarlyMD5 := md5.Sum([]byte(featureEarly))
	featureEarlyDir := fmt.Sprintf("/.envbuilder/features/aaa-early-%x", featureEarlyMD5[:4])
	featureLateMD5 := md5.Sum([]byte(featureLate))
	featureLateDir := fmt.Sprintf("/.envbuilder/features/zzz-late-%x", featureLateMD5[:4])

	t.Run("DependsOnSatisfied", func(t *testing.T) {
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureA + `": {},
    "` + featureB + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		_, err = dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)
	})

	t.Run("DependsOnAutoAdded", func(t *testing.T) {
		// featureB requires featureA, but featureA is not explicitly listed.
		// Per spec, featureA should be automatically fetched and added to the
		// install set.
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureB + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		// featureA (dep of featureB) must be present and installed before featureB.
		featureAMD5 := md5.Sum([]byte(featureA))
		featureADir := fmt.Sprintf("/.envbuilder/features/a-%x", featureAMD5[:4])
		featureBMD5 := md5.Sum([]byte(featureB))
		featureBDir := fmt.Sprintf("/.envbuilder/features/b-%x", featureBMD5[:4])
		aIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureADir)
		bIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureBDir)
		require.Greater(t, aIdx, -1, "auto-added featureA should be present in Dockerfile")
		require.Greater(t, bIdx, -1, "featureB should be present in Dockerfile")
		require.Less(t, aIdx, bIdx, "featureA should be installed before featureB (dependsOn)")
	})

	t.Run("DependsOnEnforcesInstallOrder", func(t *testing.T) {
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureEarly + `": {},
    "` + featureLate + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		earlyIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureEarlyDir)
		lateIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureLateDir)
		require.Greater(t, earlyIdx, -1, "early feature should be present")
		require.Greater(t, lateIdx, -1, "late feature should be present")
		require.Less(t, lateIdx, earlyIdx, "late should be installed before early due to dependsOn")
	})

	t.Run("OverridePinnedFreeDependsOnSucceeds", func(t *testing.T) {
		// featureEarly is pinned via overrideFeatureInstallOrder; it depends on
		// featureLate which is in the free (topo-sorted) set. Per spec, the
		// free set is installed before pinned features, so this is valid.
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureEarly + `": {},
    "` + featureLate + `": {}
  },
  "overrideFeatureInstallOrder": ["` + featureEarly + `"]
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		// featureLate (free/topo) must appear before featureEarly (pinned).
		earlyIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureEarlyDir)
		lateIdx := strings.Index(params.DockerfileContent, "WORKDIR "+featureLateDir)
		require.Greater(t, earlyIdx, -1, "early feature should be present")
		require.Greater(t, lateIdx, -1, "late feature should be present")
		require.Less(t, lateIdx, earlyIdx, "late (free) must be installed before early (pinned)")
	})

	t.Run("OverridePinnedBeforePinnedDepErrors", func(t *testing.T) {
		// Both featureEarly and featureLate are pinned, but featureEarly
		// (which depends on featureLate) is listed first — a true violation.
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureEarly + `": {},
    "` + featureLate + `": {}
  },
  "overrideFeatureInstallOrder": ["` + featureEarly + `", "` + featureLate + `"]
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		_, err = dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.ErrorContains(t, err, "overrideFeatureInstallOrder violates dependsOn")
	})

	t.Run("DependsOnCanonicalRefResolved", func(t *testing.T) {
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureByRef + `": {},
    "` + featureLate + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		_, err = dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)
	})

	t.Run("DependsOnCanonicalRefAmbiguousErrors", func(t *testing.T) {
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureByRef + `": {},
    "` + featureLateV1 + `": {},
    "` + featureLateV2 + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		_, err = dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.ErrorContains(t, err, "ambiguous canonical feature reference")
	})
}

// TestCompileWithFeaturesEqualityDeduplication covers the spec requirement
// that two features with the same ID and version are equal and must only be
// installed once, regardless of how they are referenced.
// See https://containers.dev/implementors/features/#definition-feature-equality
func TestCompileWithFeaturesEqualityDeduplication(t *testing.T) {
	t.Parallel()
	registry := registrytest.New(t)

	// Same feature content published at two different OCI tags.
	// Both have ID="shared" and Version="1.0.0" → they are equal per spec.
	featureSharedV1 := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/shared:1.0.0", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "shared",
			Version: "1.0.0",
			Name:    "Shared",
		},
	})
	featureSharedLatest := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/shared:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "shared",
			Version: "1.0.0",
			Name:    "Shared",
		},
	})

	// Two distinct features whose IDs collide at different versions.
	featureDockerV1 := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/docker:1.0", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "docker",
			Version: "1.0",
			Name:    "Docker",
		},
	})
	featureDockerV2 := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/docker:2.0", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:      "docker",
			Version: "2.0",
			Name:    "Docker",
		},
	})

	// A third feature that depends on "shared" by ID, used to verify that
	// deduplication does not break dependency satisfaction.
	featureConsumer := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/consumer:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:        "consumer",
			Version:   "1.0.0",
			Name:      "Consumer",
			DependsOn: map[string]map[string]any{"shared": {}},
		},
	})

	t.Run("SameIDSameVersionDeduplicates", func(t *testing.T) {
		// Listing the same feature via two different OCI refs (same ID+version)
		// must result in exactly one installation.
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureSharedV1 + `": {},
    "` + featureSharedLatest + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		// Only one WORKDIR for "shared" must appear, regardless of which raw ref
		// was extracted first.
		count := strings.Count(params.DockerfileContent, "/.envbuilder/features/shared-")
		require.Equal(t, 1, count, "equal features (same ID+version) must be installed exactly once")
	})

	t.Run("SameIDDifferentVersionErrors", func(t *testing.T) {
		// Requesting two different versions of the same feature ID in the same
		// install set is an error: the implementation cannot know which version
		// to satisfy dependsOn edges against.
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureDockerV1 + `": {},
    "` + featureDockerV2 + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		_, err = dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.ErrorContains(t, err, "conflicting versions")
		require.ErrorContains(t, err, "docker")
	})

	t.Run("DependsOnSatisfiedByDedupedRef", func(t *testing.T) {
		// featureConsumer depends on "shared" (by ID). Both featureSharedV1 and
		// featureSharedLatest are in the features list; they are equal and will be
		// deduped. The dependsOn must still be satisfied by the surviving entry.
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureSharedV1 + `": {},
    "` + featureSharedLatest + `": {},
    "` + featureConsumer + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err, "dependsOn must be satisfied even when the dep was deduped")

		// Exactly one installation of "shared".
		count := strings.Count(params.DockerfileContent, "/.envbuilder/features/shared-")
		require.Equal(t, 1, count, "deduped equal feature must appear only once")

		// "shared" must come before "consumer".
		consumerMD5 := md5.Sum([]byte(featureConsumer))
		consumerDir := fmt.Sprintf("/.envbuilder/features/consumer-%x", consumerMD5[:4])
		sharedIdx := strings.Index(params.DockerfileContent, "/.envbuilder/features/shared-")
		consumerIdx := strings.Index(params.DockerfileContent, "WORKDIR "+consumerDir)
		require.Greater(t, sharedIdx, -1, "shared feature must be present")
		require.Greater(t, consumerIdx, -1, "consumer feature must be present")
		require.Less(t, sharedIdx, consumerIdx, "shared must be installed before consumer (dependsOn)")
	})

	t.Run("AutoAddedDepDeduplicates", func(t *testing.T) {
		// featureConsumer depends on "shared". featureSharedLatest is explicitly
		// listed. featureSharedV1 is the auto-added transitive dep that would be
		// fetched to satisfy the dependsOn — but since "shared" is already
		// covered (id already in idToRef), no second installation should occur.
		raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureSharedLatest + `": {},
    "` + featureConsumer + `": {}
  }
}`
		dc, err := devcontainer.Parse([]byte(raw))
		require.NoError(t, err)
		fs := memfs.New()

		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		count := strings.Count(params.DockerfileContent, "/.envbuilder/features/shared-")
		require.Equal(t, 1, count, "auto-add must not install a second copy of an already-present feature")
	})
}

func TestResolveInstallOrderCycleDetection(t *testing.T) {
	t.Parallel()
	registry := registrytest.New(t)

	// featureX installsAfter featureY, featureY installsAfter featureX — a cycle.
	featureX := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/x:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:            "x",
			Version:       "1.0.0",
			Name:          "X",
			InstallsAfter: []string{"y"},
		},
	})
	featureY := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/y:latest", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:            "y",
			Version:       "1.0.0",
			Name:          "Y",
			InstallsAfter: []string{"x"},
		},
	})

	raw := `{
  "image": "localhost:5000/envbuilder-test-ubuntu:latest",
  "features": {
    "` + featureX + `": {},
    "` + featureY + `": {}
  }
}`
	dc, err := devcontainer.Parse([]byte(raw))
	require.NoError(t, err)
	fs := memfs.New()

	_, err = dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
	require.ErrorContains(t, err, "cycle detected")
}

func TestCompileDevContainer(t *testing.T) {
	t.Parallel()
	t.Run("WithImage", func(t *testing.T) {
		t.Parallel()
		fs := memfs.New()
		dc := &devcontainer.Spec{
			Image: "localhost:5000/envbuilder-test-ubuntu:latest",
		}
		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(workingDir, "Dockerfile"), params.DockerfilePath)
		require.Equal(t, workingDir, params.BuildContext)
	})
	t.Run("WithBuild", func(t *testing.T) {
		t.Parallel()
		fs := memfs.New()
		dc := &devcontainer.Spec{
			Build: devcontainer.BuildSpec{
				Dockerfile: "Dockerfile",
				Context:    ".",
				Args: map[string]string{
					"ARG1": "value1",
					"ARG2": "${localWorkspaceFolderBasename}",
				},
			},
		}
		dcDir := "/workspaces/coder/.devcontainer"
		err := fs.MkdirAll(dcDir, 0o755)
		require.NoError(t, err)
		file, err := fs.OpenFile(filepath.Join(dcDir, "Dockerfile"), os.O_CREATE|os.O_WRONLY, 0o644)
		require.NoError(t, err)
		_, err = io.WriteString(file, "FROM localhost:5000/envbuilder-test-ubuntu:latest")
		require.NoError(t, err)
		_ = file.Close()
		params, err := dc.Compile(fs, dcDir, workingDir, "", "/var/workspace", false, stubLookupEnv)
		require.NoError(t, err)
		require.Equal(t, "ARG1=value1", params.BuildArgs[0])
		require.Equal(t, "ARG2=workspace", params.BuildArgs[1])
		require.Equal(t, filepath.Join(dcDir, "Dockerfile"), params.DockerfilePath)
		require.Equal(t, dcDir, params.BuildContext)
	})
}

func TestImageFromDockerfile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		content string
		image   string
	}{{
		content: "FROM ubuntu",
		image:   "index.docker.io/library/ubuntu:latest",
	}, {
		content: "ARG VARIANT=bionic\nFROM ubuntu:$VARIANT",
		image:   "index.docker.io/library/ubuntu:bionic",
	}, {
		content: "ARG VARIANT=\"3.10\"\nFROM mcr.microsoft.com/devcontainers/python:0-${VARIANT}",
		image:   "mcr.microsoft.com/devcontainers/python:0-3.10",
	}, {
		content: "ARG VARIANT=\"3.10\"\nFROM mcr.microsoft.com/devcontainers/python:0-$VARIANT ",
		image:   "mcr.microsoft.com/devcontainers/python:0-3.10",
	}} {
		tc := tc
		t.Run(tc.image, func(t *testing.T) {
			t.Parallel()
			ref, err := devcontainer.ImageFromDockerfile(tc.content, nil)
			require.NoError(t, err)
			require.Equal(t, tc.image, ref.Name())
		})
	}
}

func TestImageFromDockerfile_BuildArgs(t *testing.T) {
	t.Parallel()

	// Test that build args override ARG defaults.
	t.Run("OverridesDefault", func(t *testing.T) {
		t.Parallel()
		content := "ARG VARIANT=3.10\nFROM mcr.microsoft.com/devcontainers/python:0-${VARIANT}"
		ref, err := devcontainer.ImageFromDockerfile(content, map[string]string{"VARIANT": "3.11-bookworm"})
		require.NoError(t, err)
		require.Equal(t, "mcr.microsoft.com/devcontainers/python:0-3.11-bookworm", ref.Name())
	})

	// Test that build args supply values for ARGs without defaults.
	t.Run("SuppliesArgWithoutDefault", func(t *testing.T) {
		t.Parallel()
		content := "ARG VARIANT\nFROM mcr.microsoft.com/devcontainers/python:1-${VARIANT}"
		ref, err := devcontainer.ImageFromDockerfile(content, map[string]string{"VARIANT": "3.11-bookworm"})
		require.NoError(t, err)
		require.Equal(t, "mcr.microsoft.com/devcontainers/python:1-3.11-bookworm", ref.Name())
	})
}

func TestUserFromDockerfile_BuildArgs(t *testing.T) {
	t.Parallel()

	t.Run("SubstitutesARGInFROM", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		image, err := partial.UncompressedToImage(emptyImage{configFile: &v1.ConfigFile{
			Config: v1.Config{
				User: "testuser",
			},
		}})
		require.NoError(t, err)
		ref := strings.TrimPrefix(registry, "http://") + "/coder/test:latest"
		parsed, err := name.ParseReference(ref)
		require.NoError(t, err)
		err = remote.Write(parsed, image)
		require.NoError(t, err)

		// Dockerfile uses ARG without default for the image ref.
		content := fmt.Sprintf("ARG TAG\nFROM %s/coder/test:${TAG}", strings.TrimPrefix(registry, "http://"))
		user, err := devcontainer.UserFromDockerfile(content, map[string]string{"TAG": "latest"})
		require.NoError(t, err)
		require.Equal(t, "testuser", user)
	})
}

func TestUserFrom(t *testing.T) {
	t.Parallel()

	t.Run("Image", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		image, err := partial.UncompressedToImage(emptyImage{configFile: &v1.ConfigFile{
			Config: v1.Config{
				User: "example",
			},
		}})
		require.NoError(t, err)

		parsed, err := url.Parse("http://" + registry)
		require.NoError(t, err)
		parsed.Path = "coder/test:latest"
		ref, err := name.ParseReference(strings.TrimPrefix(parsed.String(), "http://"))
		require.NoError(t, err)
		err = remote.Write(ref, image)
		require.NoError(t, err)

		user, err := devcontainer.UserFromImage(ref)
		require.NoError(t, err)
		require.Equal(t, "example", user)
	})

	t.Run("Dockerfile", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name    string
			content string
			user    string
		}{
			{
				name:    "Empty",
				content: "FROM scratch",
				user:    "",
			},
			{
				name:    "User",
				content: "FROM scratch\nUSER kyle",
				user:    "kyle",
			},
			{
				name:    "Env with default",
				content: "FROM scratch\nENV MYUSER=maf\nUSER ${MYUSER}",
				user:    "${MYUSER}", // This should be "maf" but the current implementation doesn't support this.
			},
			{
				name:    "Env var with default",
				content: "FROM scratch\nUSER ${MYUSER:-maf}",
				user:    "${MYUSER:-maf}", // This should be "maf" but the current implementation doesn't support this.
			},
			{
				name:    "Arg",
				content: "FROM scratch\nARG MYUSER\nUSER ${MYUSER}",
				user:    "${MYUSER}", // This should be "" or populated but the current implementation doesn't support this.
			},
			{
				name:    "Arg with default",
				content: "FROM scratch\nARG MYUSER=maf\nUSER ${MYUSER}",
				user:    "${MYUSER}", // This should be "maf" but the current implementation doesn't support this.
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				user, err := devcontainer.UserFromDockerfile(tt.content, nil)
				require.NoError(t, err)
				require.Equal(t, tt.user, user)
			})
		}
	})

	t.Run("Multi-stage", func(t *testing.T) {
		t.Parallel()

		registry := registrytest.New(t)
		for tag, user := range map[string]string{
			"one": "maf",
			"two": "fam",
		} {
			image, err := partial.UncompressedToImage(emptyImage{configFile: &v1.ConfigFile{
				Config: v1.Config{
					User: user,
				},
			}})
			require.NoError(t, err)
			parsed, err := url.Parse("http://" + registry)
			require.NoError(t, err)
			parsed.Path = "coder/test:" + tag
			ref, err := name.ParseReference(strings.TrimPrefix(parsed.String(), "http://"))
			fmt.Println(ref)
			require.NoError(t, err)
			err = remote.Write(ref, image)
			require.NoError(t, err)
		}

		tests := []struct {
			name    string
			images  map[string]string
			content string
			user    string
		}{
			{
				name:    "Single",
				content: "FROM coder/test:one",
				user:    "maf",
			},
			{
				name:    "Multi",
				content: "FROM ubuntu AS u\nFROM coder/test:two",
				user:    "fam",
			},
			{
				name:    "Multi-2",
				content: "FROM coder/test:two AS two\nUSER maffam\nFROM coder/test:one AS one",
				user:    "maf",
			},
			{
				name:    "Multi-3",
				content: "FROM coder/test:two AS two\nFROM coder/test:one AS one\nUSER fammaf",
				user:    "fammaf",
			},
			{
				name: "Multi-4",
				content: `FROM ubuntu AS a
USER root
RUN useradd --create-home pickme
USER pickme
FROM a AS other
USER root
RUN useradd --create-home notme
USER notme
FROM a`,
				user: "pickme",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				content := strings.ReplaceAll(tt.content, "coder/test", strings.TrimPrefix(registry, "http://")+"/coder/test")

				user, err := devcontainer.UserFromDockerfile(content, nil)
				require.NoError(t, err)
				require.Equal(t, tt.user, user)
			})
		}
	})
}

type emptyImage struct {
	configFile *v1.ConfigFile
}

func (i emptyImage) MediaType() (types.MediaType, error) {
	return types.DockerManifestSchema2, nil
}

func (i emptyImage) RawConfigFile() ([]byte, error) {
	return partial.RawConfigFile(i)
}

func (i emptyImage) ConfigFile() (*v1.ConfigFile, error) {
	return i.configFile, nil
}

func (i emptyImage) LayerByDiffID(h v1.Hash) (partial.UncompressedLayer, error) {
	return nil, fmt.Errorf("LayerByDiffID(%s): empty image", h)
}
