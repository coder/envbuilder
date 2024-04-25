package envbuilder

import (
	"testing"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindDevcontainerJSON(t *testing.T) {
	t.Parallel()

	t.Run("empty filesystem", func(t *testing.T) {
		t.Parallel()

		// given
		fs := memfs.New()

		// when
		_, _, err := findDevcontainerJSON(Options{WorkspaceFolder: "/workspace"}, fs, nil)

		// then
		require.Error(t, err)
	})

	t.Run("devcontainers.json is missing", func(t *testing.T) {
		t.Parallel()

		// given
		fs := memfs.New()
		err := fs.MkdirAll("/workspace/.devcontainer", 0600)
		require.NoError(t, err)

		// when
		_, _, err = findDevcontainerJSON(Options{WorkspaceFolder: "/workspace"}, fs, nil)

		// then
		require.Error(t, err)
	})

	t.Run("default configuration", func(t *testing.T) {
		t.Parallel()

		// given
		fs := memfs.New()
		err := fs.MkdirAll("/workspace/.devcontainer", 0600)
		require.NoError(t, err)
		fs.Create("/workspace/.devcontainer/devcontainer.json")

		// when
		devcontainerPath, devcontainerDir, err := findDevcontainerJSON(Options{WorkspaceFolder: "/workspace"}, fs, nil)

		// then
		require.NoError(t, err)
		assert.Equal(t, "/workspace/.devcontainer/devcontainer.json", devcontainerPath)
		assert.Equal(t, "/workspace/.devcontainer", devcontainerDir)
	})

	t.Run("overridden .devcontainer directory", func(t *testing.T) {
		t.Parallel()

		// given
		fs := memfs.New()
		err := fs.MkdirAll("/workspace/experimental-devcontainer", 0600)
		require.NoError(t, err)
		fs.Create("/workspace/experimental-devcontainer/devcontainer.json")

		// when
		c := Options{
			WorkspaceFolder: "/workspace",
			DevcontainerDir: "experimental-devcontainer",
		}
		devcontainerPath, devcontainerDir, err := findDevcontainerJSON(c, fs, nil)

		// then
		require.NoError(t, err)
		assert.Equal(t, "/workspace/experimental-devcontainer/devcontainer.json", devcontainerPath)
		assert.Equal(t, "/workspace/experimental-devcontainer", devcontainerDir)
	})

	t.Run("overridden devcontainer.json path", func(t *testing.T) {
		t.Parallel()

		// given
		fs := memfs.New()
		err := fs.MkdirAll("/workspace/.devcontainer", 0600)
		require.NoError(t, err)
		fs.Create("/workspace/.devcontainer/experimental.json")

		// when
		c := Options{
			WorkspaceFolder:      "/workspace",
			DevcontainerJSONPath: "experimental.json",
		}
		devcontainerPath, devcontainerDir, err := findDevcontainerJSON(c, fs, nil)

		// then
		require.NoError(t, err)
		assert.Equal(t, "/workspace/.devcontainer/experimental.json", devcontainerPath)
		assert.Equal(t, "/workspace/.devcontainer", devcontainerDir)
	})

	t.Run("devcontainer.json in workspace root", func(t *testing.T) {
		t.Parallel()

		// given
		fs := memfs.New()
		err := fs.MkdirAll("/workspace", 0600)
		require.NoError(t, err)
		fs.Create("/workspace/devcontainer.json")

		// when
		devcontainerPath, devcontainerDir, err := findDevcontainerJSON(Options{WorkspaceFolder: "/workspace"}, fs, nil)

		// then
		require.NoError(t, err)
		assert.Equal(t, "/workspace/devcontainer.json", devcontainerPath)
		assert.Equal(t, "/workspace", devcontainerDir)
	})

	t.Run("devcontainer.json in subfolder of .devcontainer", func(t *testing.T) {
		t.Parallel()

		// given
		fs := memfs.New()
		err := fs.MkdirAll("/workspace/.devcontainer/sample", 0600)
		require.NoError(t, err)
		fs.Create("/workspace/.devcontainer/sample/devcontainer.json")

		// when
		devcontainerPath, devcontainerDir, err := findDevcontainerJSON(Options{WorkspaceFolder: "/workspace"}, fs, nil)

		// then
		require.NoError(t, err)
		assert.Equal(t, "/workspace/.devcontainer/sample/devcontainer.json", devcontainerPath)
		assert.Equal(t, "/workspace/.devcontainer/sample", devcontainerDir)
	})
}
