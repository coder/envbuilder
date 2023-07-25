package devcontainer_test

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/devcontainer"
	"github.com/coder/envbuilder/registrytest"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

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

func TestCompileDevContainer(t *testing.T) {
	t.Parallel()
	t.Run("WithImage", func(t *testing.T) {
		t.Parallel()
		fs := memfs.New()
		dc := &devcontainer.Spec{
			Image: "codercom/code-server:latest",
		}
		params, err := dc.Compile(fs, "", envbuilder.MagicDir, "")
		require.NoError(t, err)
		require.Equal(t, filepath.Join(envbuilder.MagicDir, "Dockerfile"), params.DockerfilePath)
		require.Equal(t, envbuilder.MagicDir, params.BuildContext)
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
				},
			},
		}
		dcDir := "/workspaces/coder/.devcontainer"
		err := fs.MkdirAll(dcDir, 0755)
		require.NoError(t, err)
		file, err := fs.OpenFile(filepath.Join(dcDir, "Dockerfile"), os.O_CREATE|os.O_WRONLY, 0644)
		require.NoError(t, err)
		_, err = io.WriteString(file, "FROM ubuntu")
		require.NoError(t, err)
		_ = file.Close()
		params, err := dc.Compile(fs, dcDir, envbuilder.MagicDir, "")
		require.NoError(t, err)
		require.Equal(t, "ARG1=value1", params.BuildArgs[0])
		require.Equal(t, filepath.Join(dcDir, "Dockerfile"), params.DockerfilePath)
		require.Equal(t, dcDir, params.BuildContext)
	})
}

func TestUserFromDockerfile(t *testing.T) {
	t.Parallel()
	user := devcontainer.UserFromDockerfile("FROM ubuntu\nUSER kyle")
	require.Equal(t, "kyle", user)
}

func TestUserFromImage(t *testing.T) {
	t.Parallel()
	registry := registrytest.New(t)
	image, err := partial.UncompressedToImage(emptyImage{configFile: &v1.ConfigFile{
		Config: v1.Config{
			User: "example",
		},
	}})
	require.NoError(t, err)

	parsed, err := url.Parse(registry)
	require.NoError(t, err)
	parsed.Path = "coder/test:latest"
	ref, err := name.ParseReference(strings.TrimPrefix(parsed.String(), "http://"))
	require.NoError(t, err)
	err = remote.Write(ref, image)
	require.NoError(t, err)

	user, err := devcontainer.UserFromImage(ref)
	require.NoError(t, err)
	require.Equal(t, "example", user)
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
