package envbuilder_test

import (
	"context"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/gittest"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/stretchr/testify/require"
)

func TestCloneRepo(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		srvUsername string
		srvPassword string
		username    string
		password    string
		mungeURL    func(*string)
		expectError string
		expectClone bool
	}{
		{
			name:        "no auth",
			expectClone: true,
		},
		{
			name:        "auth",
			srvUsername: "user",
			srvPassword: "password",
			username:    "user",
			password:    "password",
			expectClone: true,
		},
		{
			name:        "auth but no creds",
			srvUsername: "user",
			srvPassword: "password",
			expectClone: false,
			expectError: "authentication required",
		},
		{
			name:        "invalid auth",
			srvUsername: "user",
			srvPassword: "password",
			username:    "notuser",
			password:    "notpassword",
			expectClone: false,
			expectError: "authentication required",
		},
		{
			name:        "tokenish username",
			srvUsername: "tokentokentoken",
			srvPassword: "",
			username:    "tokentokentoken",
			password:    "",
			expectClone: true,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// We do not overwrite a repo if one is already present.
			t.Run("AlreadyCloned", func(t *testing.T) {
				srvURL := setupGit(t, tc.srvUsername, tc.srvPassword)
				clientFS := memfs.New()
				// A repo already exists!
				_ = gittest.NewRepo(t, clientFS)
				cloned, err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
					Path:    "/",
					RepoURL: srvURL,
					Storage: clientFS,
				})
				require.NoError(t, err)
				require.False(t, cloned)
			})

			// Basic Auth
			t.Run("BasicAuth", func(t *testing.T) {
				t.Parallel()
				srvURL := setupGit(t, tc.srvUsername, tc.srvPassword)
				clientFS := memfs.New()

				cloned, err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
					Path:    "/workspace",
					RepoURL: srvURL,
					Storage: clientFS,
					RepoAuth: &githttp.BasicAuth{
						Username: tc.username,
						Password: tc.password,
					},
				})
				require.Equal(t, tc.expectClone, cloned)
				if tc.expectError != "" {
					require.ErrorContains(t, err, tc.expectError)
					return
				}
				require.NoError(t, err)
				require.True(t, cloned)

				readme := mustRead(t, clientFS, "/workspace/README.md")
				require.Equal(t, "Hello, world!", readme)
				gitConfig := mustRead(t, clientFS, "/workspace/.git/config")
				// Ensure we do not modify the git URL that folks pass in.
				require.Regexp(t, fmt.Sprintf(`(?m)^\s+url\s+=\s+%s\s*$`, regexp.QuoteMeta(srvURL)), gitConfig)
			})

			// In-URL-style auth e.g. http://user:password@host:port
			t.Run("InURL", func(t *testing.T) {
				t.Parallel()
				srvURL := setupGit(t, tc.srvUsername, tc.srvPassword)
				authURL, err := url.Parse(srvURL)
				require.NoError(t, err)
				authURL.User = url.UserPassword(tc.username, tc.password)
				clientFS := memfs.New()

				cloned, err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
					Path:    "/workspace",
					RepoURL: authURL.String(),
					Storage: clientFS,
				})
				require.Equal(t, tc.expectClone, cloned)
				if tc.expectError != "" {
					require.ErrorContains(t, err, tc.expectError)
					return
				}
				require.NoError(t, err)
				require.True(t, cloned)

				readme := mustRead(t, clientFS, "/workspace/README.md")
				require.Equal(t, "Hello, world!", readme)
				gitConfig := mustRead(t, clientFS, "/workspace/.git/config")
				// Ensure we do not modify the git URL that folks pass in.
				require.Regexp(t, fmt.Sprintf(`(?m)^\s+url\s+=\s+%s\s*$`, regexp.QuoteMeta(authURL.String())), gitConfig)
			})
		})
	}
}

func mustRead(t *testing.T, fs billy.Filesystem, path string) string {
	t.Helper()
	f, err := fs.OpenFile(path, os.O_RDONLY, 0644)
	require.NoError(t, err)
	content, err := io.ReadAll(f)
	require.NoError(t, err)
	return string(content)
}

func setupGit(t *testing.T, user, pass string) (url string) {
	serverFS := memfs.New()
	repo := gittest.NewRepo(t, serverFS)
	tree, err := repo.Worktree()
	require.NoError(t, err)

	gittest.WriteFile(t, serverFS, "README.md", "Hello, world!")
	_, err = tree.Add("README.md")
	require.NoError(t, err)
	commit, err := tree.Commit("Wow!", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Example",
			Email: "in@tests.com",
			When:  time.Now(),
		},
	})
	require.NoError(t, err)
	_, err = repo.CommitObject(commit)
	require.NoError(t, err)

	authMW := gittest.BasicAuthMW(user, pass)
	srv := httptest.NewServer(authMW(gittest.NewServer(serverFS)))
	return srv.URL
}
