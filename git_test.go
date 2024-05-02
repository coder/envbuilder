package envbuilder_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"testing"

	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/testutil/gittest"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-billy/v5/osfs"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
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
				srvFS := memfs.New()
				_ = gittest.NewRepo(t, srvFS, gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
				authMW := gittest.BasicAuthMW(tc.srvUsername, tc.srvPassword)
				srv := httptest.NewServer(authMW(gittest.NewServer(srvFS)))
				clientFS := memfs.New()
				// A repo already exists!
				_ = gittest.NewRepo(t, clientFS)
				cloned, err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
					Path:    "/",
					RepoURL: srv.URL,
					Storage: clientFS,
				})
				require.NoError(t, err)
				require.False(t, cloned)
			})

			// Basic Auth
			t.Run("BasicAuth", func(t *testing.T) {
				t.Parallel()
				srvFS := memfs.New()
				_ = gittest.NewRepo(t, srvFS, gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
				authMW := gittest.BasicAuthMW(tc.srvUsername, tc.srvPassword)
				srv := httptest.NewServer(authMW(gittest.NewServer(srvFS)))
				clientFS := memfs.New()

				cloned, err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
					Path:    "/workspace",
					RepoURL: srv.URL,
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
				require.Regexp(t, fmt.Sprintf(`(?m)^\s+url\s+=\s+%s\s*$`, regexp.QuoteMeta(srv.URL)), gitConfig)
			})

			// In-URL-style auth e.g. http://user:password@host:port
			t.Run("InURL", func(t *testing.T) {
				t.Parallel()
				srvFS := memfs.New()
				_ = gittest.NewRepo(t, srvFS, gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
				authMW := gittest.BasicAuthMW(tc.srvUsername, tc.srvPassword)
				srv := httptest.NewServer(authMW(gittest.NewServer(srvFS)))

				authURL, err := url.Parse(srv.URL)
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

func TestCloneRepoSSH(t *testing.T) {
	t.Parallel()

	t.Run("AuthSuccess", func(t *testing.T) {
		t.Parallel()

		// TODO: test the rest of the cloning flow. This just tests successful auth.
		tmpDir := t.TempDir()
		srvFS := osfs.New(tmpDir, osfs.WithChrootOS())

		_ = gittest.NewRepo(t, srvFS, gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
		key := randKeygen(t)
		tr := gittest.NewServerSSH(t, srvFS, key.PublicKey())
		gitURL := tr.String()
		clientFS := memfs.New()

		cloned, err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
			Path:    "/workspace",
			RepoURL: gitURL,
			Storage: clientFS,
			RepoAuth: &gitssh.PublicKeys{
				User:   "",
				Signer: key,
				HostKeyCallbackHelper: gitssh.HostKeyCallbackHelper{
					// Not testing host keys here.
					HostKeyCallback: gossh.InsecureIgnoreHostKey(),
				},
			},
		})
		// TODO: ideally, we want to test the entire cloning flow.
		// For now, this indicates successful ssh key auth.
		require.ErrorContains(t, err, "repository not found")
		require.False(t, cloned)
	})

	t.Run("AuthFailure", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		srvFS := osfs.New(tmpDir, osfs.WithChrootOS())

		_ = gittest.NewRepo(t, srvFS, gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
		key := randKeygen(t)
		tr := gittest.NewServerSSH(t, srvFS, key.PublicKey())
		gitURL := tr.String()
		clientFS := memfs.New()

		anotherKey := randKeygen(t)
		cloned, err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
			Path:    "/workspace",
			RepoURL: gitURL,
			Storage: clientFS,
			RepoAuth: &gitssh.PublicKeys{
				User:   "",
				Signer: anotherKey,
				HostKeyCallbackHelper: gitssh.HostKeyCallbackHelper{
					// Not testing host keys here.
					HostKeyCallback: gossh.InsecureIgnoreHostKey(),
				},
			},
		})
		require.ErrorContains(t, err, "handshake failed")
		require.False(t, cloned)
	})

	// nolint: paralleltest // t.Setenv
	t.Run("PrivateKeyHostKeyMismatch", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		srvFS := osfs.New(tmpDir, osfs.WithChrootOS())

		_ = gittest.NewRepo(t, srvFS, gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
		key := randKeygen(t)
		tr := gittest.NewServerSSH(t, srvFS, key.PublicKey())
		gitURL := tr.String()
		clientFS := memfs.New()

		cloned, err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
			Path:    "/workspace",
			RepoURL: gitURL,
			Storage: clientFS,
			RepoAuth: &gitssh.PublicKeys{
				User:   "",
				Signer: key,
				HostKeyCallbackHelper: gitssh.HostKeyCallbackHelper{
					HostKeyCallback: gossh.FixedHostKey(randKeygen(t).PublicKey()),
				},
			},
		})
		require.ErrorContains(t, err, "ssh: host key mismatch")
		require.False(t, cloned)
	})
}

func TestParseGitURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		url           string
		expected      string
		expectedError string
	}{
		{
			url:      "https://user:pass@example.com/repo",
			expected: "https://user:pass@example.com/repo",
		},
		{
			url:      "http://user:pass@example.com/repo",
			expected: "http://user:pass@example.com/repo",
		},
		{
			url:      "ssh://git@example.com/repo",
			expected: "ssh://git@example.com/repo",
		},
		{
			url:      "git@example.com/repo",
			expected: "ssh://git@example.com/repo",
		},
	} {
		actual, err := envbuilder.ParseGitURL(tc.url)
		if tc.expectedError == "" {
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, actual.String())
			continue
		}
		assert.ErrorContains(t, err, tc.expectedError)
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

// generates a random ed25519 private key
func randKeygen(t *testing.T) gossh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	signer, err := gossh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}
