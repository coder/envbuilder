package envbuilder_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/coder/envbuilder"
	"github.com/coder/envbuilder/testutil/gittest"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-billy/v5/osfs"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
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

	// nolint: paralleltest // t.Setenv
	t.Run("PrivateKeyOK", func(t *testing.T) {
		t.Skip("TODO: need to figure out how to properly add advertised refs")
		// TODO: Can't we use a memfs here?
		tmpDir := t.TempDir()
		srvFS := osfs.New(tmpDir, osfs.WithChrootOS())

		signer := randKeygen(t)
		_ = gittest.NewRepo(t, srvFS, gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
		tr := gittest.NewServerSSH(t, srvFS, signer.PublicKey())
		gitURL := tr.String()
		clientFS := memfs.New()

		cloned, err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
			Path:    "/workspace",
			RepoURL: gitURL,
			Storage: clientFS,
			RepoAuth: &gitssh.PublicKeys{
				User:   "",
				Signer: signer,
				HostKeyCallbackHelper: gitssh.HostKeyCallbackHelper{
					HostKeyCallback: gossh.InsecureIgnoreHostKey(), // TODO: known_hosts
				},
			},
		})
		require.NoError(t, err) // TODO: error: repository not found
		require.True(t, cloned)

		readme := mustRead(t, clientFS, "/workspace/README.md")
		require.Equal(t, "Hello, world!", readme)
		gitConfig := mustRead(t, clientFS, "/workspace/.git/config")
		// Ensure we do not modify the git URL that folks pass in.
		require.Regexp(t, fmt.Sprintf(`(?m)^\s+url\s+=\s+%s\s*$`, regexp.QuoteMeta(gitURL)), gitConfig)
	})

	// nolint: paralleltest // t.Setenv
	t.Run("PrivateKeyError", func(t *testing.T) {
		tmpDir := t.TempDir()
		srvFS := osfs.New(tmpDir, osfs.WithChrootOS())

		signer := randKeygen(t)
		anotherSigner := randKeygen(t)
		_ = gittest.NewRepo(t, srvFS, gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
		tr := gittest.NewServerSSH(t, srvFS, signer.PublicKey())
		gitURL := tr.String()
		clientFS := memfs.New()

		cloned, err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
			Path:    "/workspace",
			RepoURL: gitURL,
			Storage: clientFS,
			RepoAuth: &gitssh.PublicKeys{
				User:   "",
				Signer: anotherSigner,
				HostKeyCallbackHelper: gitssh.HostKeyCallbackHelper{
					HostKeyCallback: gossh.InsecureIgnoreHostKey(), // TODO: known_hosts
				},
			},
		})
		require.ErrorContains(t, err, "handshake failed")
		require.False(t, cloned)
	})

	// nolint: paralleltest // t.Setenv
	t.Run("PrivateKeyHostKeyUnknown", func(t *testing.T) {
		tmpDir := t.TempDir()
		srvFS := osfs.New(tmpDir, osfs.WithChrootOS())

		knownHostsPath := filepath.Join(tmpDir, "known_hosts")
		require.NoError(t, os.WriteFile(knownHostsPath, []byte{}, 0o600))
		t.Setenv("SSH_KNOWN_HOSTS", knownHostsPath)

		signer := randKeygen(t)
		anotherSigner := randKeygen(t)
		_ = gittest.NewRepo(t, srvFS, gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
		tr := gittest.NewServerSSH(t, srvFS, signer.PublicKey())
		gitURL := tr.String()
		clientFS := memfs.New()

		cloned, err := envbuilder.CloneRepo(context.Background(), envbuilder.CloneRepoOptions{
			Path:    "/workspace",
			RepoURL: gitURL,
			Storage: clientFS,
			RepoAuth: &gitssh.PublicKeys{
				User:   "",
				Signer: anotherSigner,
			},
		})
		require.ErrorContains(t, err, "key is unknown")
		require.False(t, cloned)
	})
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
