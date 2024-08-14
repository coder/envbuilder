package envbuilder

import (
	"context"
	"testing"
	"time"

	"github.com/coder/envbuilder/options"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunCacheProbe(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		files         map[string]string
		mutateOptions func(*options.Options)
		assertImage   func(v1.Image)
		assertError   func(error)
	}{} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.assertError == nil && tc.assertImage == nil {
				require.Failf(t, "%s: either assertError or assertImage must be defined", tc.name)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			t.Cleanup(cancel)
			var opts options.Options
			img, err := RunCacheProbe(ctx, opts)
			if tc.assertImage != nil {
				tc.assertImage(img)
			}
			if tc.assertError != nil {
				tc.assertError(err)
			}
		})
	}
}

func TestFindDevcontainerJSON(t *testing.T) {
	t.Parallel()

	defaultWorkspaceFolder := "/workspace"

	for _, tt := range []struct {
		name            string
		workspaceFolder string
	}{
		{
			name:            "Default",
			workspaceFolder: defaultWorkspaceFolder,
		},
		{
			name:            "RepoMode",
			workspaceFolder: "/.envbuilder/repo",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			t.Run("empty filesystem", func(t *testing.T) {
				t.Parallel()

				// given
				fs := memfs.New()

				// when
				_, _, err := findDevcontainerJSON(tt.workspaceFolder, options.Options{
					Filesystem:      fs,
					WorkspaceFolder: "/workspace",
				})

				// then
				require.Error(t, err)
			})

			t.Run("devcontainer.json is missing", func(t *testing.T) {
				t.Parallel()

				// given
				fs := memfs.New()
				err := fs.MkdirAll(tt.workspaceFolder+"/.devcontainer", 0o600)
				require.NoError(t, err)

				// when
				_, _, err = findDevcontainerJSON(tt.workspaceFolder, options.Options{
					Filesystem:      fs,
					WorkspaceFolder: "/workspace",
				})

				// then
				require.Error(t, err)
			})

			t.Run("default configuration", func(t *testing.T) {
				t.Parallel()

				// given
				fs := memfs.New()
				err := fs.MkdirAll(tt.workspaceFolder+"/.devcontainer", 0o600)
				require.NoError(t, err)
				_, err = fs.Create(tt.workspaceFolder + "/.devcontainer/devcontainer.json")
				require.NoError(t, err)

				// when
				devcontainerPath, devcontainerDir, err := findDevcontainerJSON(tt.workspaceFolder, options.Options{
					Filesystem:      fs,
					WorkspaceFolder: "/workspace",
				})

				// then
				require.NoError(t, err)
				assert.Equal(t, tt.workspaceFolder+"/.devcontainer/devcontainer.json", devcontainerPath)
				assert.Equal(t, tt.workspaceFolder+"/.devcontainer", devcontainerDir)
			})

			t.Run("overridden .devcontainer directory", func(t *testing.T) {
				t.Parallel()

				// given
				fs := memfs.New()
				err := fs.MkdirAll(tt.workspaceFolder+"/experimental-devcontainer", 0o600)
				require.NoError(t, err)
				_, err = fs.Create(tt.workspaceFolder + "/experimental-devcontainer/devcontainer.json")
				require.NoError(t, err)

				// when
				devcontainerPath, devcontainerDir, err := findDevcontainerJSON(tt.workspaceFolder, options.Options{
					Filesystem:      fs,
					WorkspaceFolder: "/workspace",
					DevcontainerDir: "experimental-devcontainer",
				})

				// then
				require.NoError(t, err)
				assert.Equal(t, tt.workspaceFolder+"/experimental-devcontainer/devcontainer.json", devcontainerPath)
				assert.Equal(t, tt.workspaceFolder+"/experimental-devcontainer", devcontainerDir)
			})

			t.Run("overridden devcontainer.json path", func(t *testing.T) {
				t.Parallel()

				// given
				fs := memfs.New()
				err := fs.MkdirAll(tt.workspaceFolder+"/.devcontainer", 0o600)
				require.NoError(t, err)
				_, err = fs.Create(tt.workspaceFolder + "/.devcontainer/experimental.json")
				require.NoError(t, err)

				// when
				devcontainerPath, devcontainerDir, err := findDevcontainerJSON(tt.workspaceFolder, options.Options{
					Filesystem:           fs,
					WorkspaceFolder:      "/workspace",
					DevcontainerJSONPath: "experimental.json",
				})

				// then
				require.NoError(t, err)
				assert.Equal(t, tt.workspaceFolder+"/.devcontainer/experimental.json", devcontainerPath)
				assert.Equal(t, tt.workspaceFolder+"/.devcontainer", devcontainerDir)
			})

			t.Run("devcontainer.json in workspace root", func(t *testing.T) {
				t.Parallel()

				// given
				fs := memfs.New()
				err := fs.MkdirAll(tt.workspaceFolder+"", 0o600)
				require.NoError(t, err)
				_, err = fs.Create(tt.workspaceFolder + "/devcontainer.json")
				require.NoError(t, err)

				// when
				devcontainerPath, devcontainerDir, err := findDevcontainerJSON(tt.workspaceFolder, options.Options{
					Filesystem:      fs,
					WorkspaceFolder: "/workspace",
				})

				// then
				require.NoError(t, err)
				assert.Equal(t, tt.workspaceFolder+"/devcontainer.json", devcontainerPath)
				assert.Equal(t, tt.workspaceFolder+"", devcontainerDir)
			})

			t.Run("devcontainer.json in subfolder of .devcontainer", func(t *testing.T) {
				t.Parallel()

				// given
				fs := memfs.New()
				err := fs.MkdirAll(tt.workspaceFolder+"/.devcontainer/sample", 0o600)
				require.NoError(t, err)
				_, err = fs.Create(tt.workspaceFolder + "/.devcontainer/sample/devcontainer.json")
				require.NoError(t, err)

				// when
				devcontainerPath, devcontainerDir, err := findDevcontainerJSON(tt.workspaceFolder, options.Options{
					Filesystem:      fs,
					WorkspaceFolder: "/workspace",
				})

				// then
				require.NoError(t, err)
				assert.Equal(t, tt.workspaceFolder+"/.devcontainer/sample/devcontainer.json", devcontainerPath)
				assert.Equal(t, tt.workspaceFolder+"/.devcontainer/sample", devcontainerDir)
			})
		})
	}
}
