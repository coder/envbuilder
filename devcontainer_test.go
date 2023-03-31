package envbuilder_test

import (
	"path/filepath"
	"testing"

	"github.com/coder/envbuilder"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/stretchr/testify/require"
)

func TestParseDevContainer(t *testing.T) {
	t.Parallel()
	raw := `{
  "build": {
    "dockerfile": "Dockerfile",
    "context": "."
  },
  // Comments here!
  "image": "codercom/code-server:latest"
}`
	parsed, err := envbuilder.ParseDevcontainer([]byte(raw))
	require.NoError(t, err)
	require.Equal(t, "Dockerfile", parsed.Build.Dockerfile)
}

func TestCompileDevContainer(t *testing.T) {
	t.Parallel()
	t.Run("WithImage", func(t *testing.T) {
		t.Parallel()
		fs := memfs.New()
		dc := &envbuilder.DevContainer{
			Image: "codercom/code-server:latest",
		}
		params, err := dc.Compile(fs, "", envbuilder.MagicDir)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(envbuilder.MagicDir, "Dockerfile"), params.DockerfilePath)
		require.Equal(t, envbuilder.MagicDir, params.BuildContext)
	})
	t.Run("WithBuild", func(t *testing.T) {
		t.Parallel()
		fs := memfs.New()
		dc := &envbuilder.DevContainer{
			Build: envbuilder.DevContainerBuild{
				Dockerfile: "Dockerfile",
				Context:    ".",
				Args: map[string]string{
					"ARG1": "value1",
				},
			},
		}
		dcDir := "/workspaces/coder/.devcontainer"
		err := fs.MkdirAll(dcDir, 0755)
		require.NoError(t, err)
		params, err := dc.Compile(fs, dcDir, envbuilder.MagicDir)
		require.NoError(t, err)
		require.Equal(t, "ARG1=value1", params.BuildArgs[0])
		require.Equal(t, filepath.Join(dcDir, "Dockerfile"), params.DockerfilePath)
		require.Equal(t, dcDir, params.BuildContext)
	})
}
