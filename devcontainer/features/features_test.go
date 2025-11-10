package features_test

import (
	"strings"
	"testing"

	"github.com/coder/envbuilder/devcontainer/features"
	"github.com/coder/envbuilder/testutil/registrytest"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
)

var emptyRemoteOpts []remote.Option

func TestExtract(t *testing.T) {
	t.Parallel()
	t.Run("MissingMediaType", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		ref := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/test:latest", "some/type", nil)
		fs := memfs.New()
		_, err := features.Extract(fs, "", "/", ref)
		require.ErrorContains(t, err, "no tar layer found")
	})
	t.Run("MissingInstallScript", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		ref := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/test:latest", features.TarLayerMediaType, map[string]any{
			"devcontainer-feature.json": "{}",
		})
		fs := memfs.New()
		_, err := features.Extract(fs, "", "/", ref)
		require.ErrorContains(t, err, "install.sh")
	})
	t.Run("MissingFeatureFile", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		ref := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/test:latest", features.TarLayerMediaType, map[string]any{
			"install.sh": "hey",
		})
		fs := memfs.New()
		_, err := features.Extract(fs, "", "/", ref)
		require.ErrorContains(t, err, "devcontainer-feature.json")
	})
	t.Run("MissingFeatureProperties", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		ref := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/test:latest", features.TarLayerMediaType, map[string]any{
			"install.sh":                "hey",
			"devcontainer-feature.json": features.Spec{},
		})
		fs := memfs.New()
		_, err := features.Extract(fs, "", "/", ref)
		require.ErrorContains(t, err, "id is required")
	})
	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		ref := registrytest.WriteContainer(t, registry, emptyRemoteOpts, "coder/test:latest", features.TarLayerMediaType, map[string]any{
			"install.sh": "hey",
			"devcontainer-feature.json": features.Spec{
				ID:      "go",
				Version: "1.0.0",
				Name:    "Go",
			},
		})
		fs := memfs.New()
		_, err := features.Extract(fs, "", "/", ref)
		require.NoError(t, err)
	})
}

func TestCompile(t *testing.T) {
	t.Parallel()
	t.Run("UnknownOption", func(t *testing.T) {
		t.Parallel()
		spec := &features.Spec{}
		_, _, err := spec.Compile("coder/test:latest", "test", "", "containerUser", "remoteUser", false, map[string]any{
			"unknown": "value",
		})
		require.ErrorContains(t, err, "unknown option")
	})
	t.Run("Basic", func(t *testing.T) {
		t.Parallel()
		spec := &features.Spec{}
		_, directive, err := spec.Compile("coder/test:latest", "test", "/", "containerUser", "remoteUser", false, nil)
		require.NoError(t, err)
		require.Equal(t, "WORKDIR /\nRUN _CONTAINER_USER=\"containerUser\" _REMOTE_USER=\"remoteUser\" ./install.sh", strings.TrimSpace(directive))
	})
	t.Run("ContainerEnv", func(t *testing.T) {
		t.Parallel()
		spec := &features.Spec{
			ContainerEnv: map[string]string{
				"FOO": "bar",
			},
		}
		_, directive, err := spec.Compile("coder/test:latest", "test", "/", "containerUser", "remoteUser", false, nil)
		require.NoError(t, err)
		require.Equal(t, "WORKDIR /\nENV FOO=bar\nRUN _CONTAINER_USER=\"containerUser\" _REMOTE_USER=\"remoteUser\" ./install.sh", strings.TrimSpace(directive))
	})
	t.Run("OptionsEnv", func(t *testing.T) {
		t.Parallel()
		spec := &features.Spec{
			Options: map[string]features.Option{
				"foo": {
					Default: "bar",
				},
			},
		}
		_, directive, err := spec.Compile("coder/test:latest", "test", "/", "containerUser", "remoteUser", false, nil)
		require.NoError(t, err)
		require.Equal(t, "WORKDIR /\nRUN FOO=\"bar\" _CONTAINER_USER=\"containerUser\" _REMOTE_USER=\"remoteUser\" ./install.sh", strings.TrimSpace(directive))
	})
	t.Run("BuildContext", func(t *testing.T) {
		t.Parallel()
		spec := &features.Spec{}
		fromDirective, runDirective, err := spec.Compile("coder/test:latest", "test", "/.envbuilder/feature/test-d8e8fc", "containerUser", "remoteUser", true, nil)
		require.NoError(t, err)
		require.Equal(t, "FROM scratch AS envbuilder_feature_test\nCOPY --from=coder/test:latest / /", strings.TrimSpace(fromDirective))
		require.Equal(t, "WORKDIR /.envbuilder/features/test\nRUN --mount=type=bind,from=envbuilder_feature_test,target=/.envbuilder/features/test,rw _CONTAINER_USER=\"containerUser\" _REMOTE_USER=\"remoteUser\" ./install.sh", strings.TrimSpace(runDirective))
	})
}
