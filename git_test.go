package envbuilder_test

import (
	"context"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/gittest"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/require"
)

func TestCloneRepo(t *testing.T) {
	t.Parallel()

	t.Run("Clones", func(t *testing.T) {
		t.Parallel()

		serverFS := memfs.New()
		repo := gittest.NewRepo(t, serverFS)
		tree, err := repo.Worktree()
		require.NoError(t, err)

		gittest.WriteFile(t, serverFS, "README.md", "Hello, world!")
		_, err = tree.Add("README.md")
		require.NoError(t, err)
		commit, err := tree.Commit("Wow!", &git.CommitOptions{})
		require.NoError(t, err)
		_, err = repo.CommitObject(commit)
		require.NoError(t, err)

		srv := httptest.NewServer(gittest.NewServer(serverFS))

		clientFS := memfs.New()
		err = envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
			Path:    "/workspace",
			RepoURL: srv.URL,
			Storage: clientFS,
		})
		require.NoError(t, err)

		file, err := clientFS.OpenFile("/workspace/README.md", os.O_RDONLY, 0644)
		require.NoError(t, err)
		defer file.Close()
		content, err := io.ReadAll(file)
		require.NoError(t, err)
		require.Equal(t, "Hello, world!", string(content))
	})

	t.Run("DoesntCloneIfRepoExists", func(t *testing.T) {
		t.Parallel()
		clientFS := memfs.New()
		gittest.NewRepo(t, clientFS)
		err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
			Path:    "/",
			RepoURL: "https://example.com",
			Storage: clientFS,
		})
		require.NoError(t, err)
	})
}
