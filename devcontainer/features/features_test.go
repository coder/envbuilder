package features_test

import (
	"strings"
	"testing"

	"github.com/coder/envbuilder/devcontainer/features"
	"github.com/coder/envbuilder/registrytest"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/stretchr/testify/require"
)

func TestExtract(t *testing.T) {
	t.Parallel()
	t.Run("MissingMediaType", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		ref := registrytest.WriteContainer(t, registry, "coder/test:latest", "some/type", nil)
		fs := memfs.New()
		_, err := features.Extract(fs, "/", ref)
		require.ErrorContains(t, err, "no tar layer found")
	})
	t.Run("MissingInstallScript", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		ref := registrytest.WriteContainer(t, registry, "coder/test:latest", features.TarLayerMediaType, map[string]any{
			"devcontainer-feature.json": "{}",
		})
		fs := memfs.New()
		_, err := features.Extract(fs, "/", ref)
		require.ErrorContains(t, err, "install.sh")
	})
	t.Run("MissingFeatureFile", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		ref := registrytest.WriteContainer(t, registry, "coder/test:latest", features.TarLayerMediaType, map[string]any{
			"install.sh": "hey",
		})
		fs := memfs.New()
		_, err := features.Extract(fs, "/", ref)
		require.ErrorContains(t, err, "devcontainer-feature.json")
	})
	t.Run("MissingFeatureProperties", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		ref := registrytest.WriteContainer(t, registry, "coder/test:latest", features.TarLayerMediaType, map[string]any{
			"install.sh":                "hey",
			"devcontainer-feature.json": features.Spec{},
		})
		fs := memfs.New()
		_, err := features.Extract(fs, "/", ref)
		require.ErrorContains(t, err, "id is required")
	})
	t.Run("Success", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		ref := registrytest.WriteContainer(t, registry, "coder/test:latest", features.TarLayerMediaType, map[string]any{
			"install.sh": "hey",
			"devcontainer-feature.json": features.Spec{
				ID:      "go",
				Version: "1.0.0",
				Name:    "Go",
			},
		})
		fs := memfs.New()
		_, err := features.Extract(fs, "/", ref)
		require.NoError(t, err)
	})
}

func TestCompile(t *testing.T) {
	t.Parallel()
	t.Run("UnknownOption", func(t *testing.T) {
		t.Parallel()
		spec := &features.Spec{}
		_, err := spec.Compile(map[string]any{
			"unknown": "value",
		})
		require.ErrorContains(t, err, "unknown option")
	})
	t.Run("Basic", func(t *testing.T) {
		t.Parallel()
		spec := &features.Spec{
			InstallScriptPath: "install.sh",
		}
		directive, err := spec.Compile(nil)
		require.NoError(t, err)
		require.Equal(t, "RUN install.sh", strings.TrimSpace(directive))
	})
	t.Run("ContainerEnv", func(t *testing.T) {
		t.Parallel()
		spec := &features.Spec{
			InstallScriptPath: "install.sh",
			ContainerEnv: map[string]string{
				"FOO": "bar",
			},
		}
		directive, err := spec.Compile(nil)
		require.NoError(t, err)
		require.Equal(t, "ENV FOO=bar\nRUN install.sh", strings.TrimSpace(directive))
	})
	t.Run("OptionsEnv", func(t *testing.T) {
		t.Parallel()
		spec := &features.Spec{
			InstallScriptPath: "install.sh",
			Options: map[string]features.Option{
				"foo": {
					Default: "bar",
				},
			},
		}
		directive, err := spec.Compile(nil)
		require.NoError(t, err)
		require.Equal(t, "RUN FOO=bar install.sh", strings.TrimSpace(directive))
	})
}
