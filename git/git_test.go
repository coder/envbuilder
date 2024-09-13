package git_test

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

	"github.com/coder/envbuilder/git"
	"github.com/coder/envbuilder/options"
	"github.com/coder/envbuilder/testutil/gittest"
	"github.com/coder/envbuilder/testutil/mwtest"

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
		prepFS      func(billy.Filesystem)
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
				_ = gittest.NewRepo(t, srvFS).Commit(gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
				authMW := mwtest.BasicAuthMW(tc.srvUsername, tc.srvPassword)
				srv := httptest.NewServer(authMW(gittest.NewServer(srvFS)))
				clientFS := memfs.New()
				// A repo already exists!
				_ = gittest.NewRepo(t, clientFS).Commit(gittest.Commit(t, "WRITEME.md", "I'm already here!", "Wow!"))
				cloned, err := git.CloneRepo(context.Background(), t.Logf, git.CloneRepoOptions{
					Path:    "/workspace",
					RepoURL: srv.URL,
					Storage: clientFS,
					RepoAuth: &githttp.BasicAuth{
						Username: tc.username,
						Password: tc.password,
					},
				})
				if tc.expectError != "" {
					assert.ErrorContains(t, err, tc.expectError)
				}
				assert.False(t, cloned)

				// Ensure we do not overwrite the existing repo.
				readme := mustRead(t, clientFS, "/workspace/WRITEME.md")
				assert.Equal(t, "I'm already here!", readme)
			})

			// Basic Auth
			t.Run("BasicAuth", func(t *testing.T) {
				t.Parallel()
				srvFS := memfs.New()
				_ = gittest.NewRepo(t, srvFS).Commit(gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
				authMW := mwtest.BasicAuthMW(tc.srvUsername, tc.srvPassword)
				srv := httptest.NewServer(authMW(gittest.NewServer(srvFS)))
				clientFS := memfs.New()

				cloned, err := git.CloneRepo(context.Background(), t.Logf, git.CloneRepoOptions{
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
				_ = gittest.NewRepo(t, srvFS).Commit(gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
				authMW := mwtest.BasicAuthMW(tc.srvUsername, tc.srvPassword)
				srv := httptest.NewServer(authMW(gittest.NewServer(srvFS)))

				authURL, err := url.Parse(srv.URL)
				require.NoError(t, err)
				authURL.User = url.UserPassword(tc.username, tc.password)
				clientFS := memfs.New()

				cloned, err := git.CloneRepo(context.Background(), t.Logf, git.CloneRepoOptions{
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

func TestShallowCloneRepo(t *testing.T) {
	t.Parallel()

	t.Run("NotEmpty", func(t *testing.T) {
		t.Parallel()
		srvFS := memfs.New()
		_ = gittest.NewRepo(t, srvFS).Commit(
			gittest.Commit(t, "README.md", "Hello, world!", "Many wow!"),
			gittest.Commit(t, "foo", "bar!", "Such commit!"),
			gittest.Commit(t, "baz", "qux", "V nice!"),
		)
		authMW := mwtest.BasicAuthMW("test", "test")
		srv := httptest.NewServer(authMW(gittest.NewServer(srvFS)))

		clientFS := memfs.New()
		// Not empty.
		err := clientFS.MkdirAll("/repo", 0o500)
		require.NoError(t, err)
		f, err := clientFS.Create("/repo/not-empty")
		require.NoError(t, err)
		require.NoError(t, f.Close())

		err = git.ShallowCloneRepo(context.Background(), t.Logf, git.CloneRepoOptions{
			Path:    "/repo",
			RepoURL: srv.URL,
			Storage: clientFS,
			RepoAuth: &githttp.BasicAuth{
				Username: "test",
				Password: "test",
			},
		})
		require.Error(t, err)
	})
	t.Run("OK", func(t *testing.T) {
		// 2024/08/01 13:22:08 unsupported capability: shallow
		// clone "http://127.0.0.1:41499": unexpected client error: unexpected requesting "http://127.0.0.1:41499/git-upload-pack" status code: 500
		t.Skip("The gittest server doesn't support shallow cloning, skip for now...")

		t.Parallel()
		srvFS := memfs.New()
		_ = gittest.NewRepo(t, srvFS).Commit(
			gittest.Commit(t, "README.md", "Hello, world!", "Many wow!"),
			gittest.Commit(t, "foo", "bar!", "Such commit!"),
			gittest.Commit(t, "baz", "qux", "V nice!"),
		)
		authMW := mwtest.BasicAuthMW("test", "test")
		srv := httptest.NewServer(authMW(gittest.NewServer(srvFS)))

		clientFS := memfs.New()

		err := git.ShallowCloneRepo(context.Background(), t.Logf, git.CloneRepoOptions{
			Path:    "/repo",
			RepoURL: srv.URL,
			Storage: clientFS,
			RepoAuth: &githttp.BasicAuth{
				Username: "test",
				Password: "test",
			},
		})
		require.NoError(t, err)
		for _, path := range []string{"README.md", "foo", "baz"} {
			_, err := clientFS.Stat(filepath.Join("/repo", path))
			require.NoError(t, err)
		}
	})
}

func TestFetchAfterClone(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	// ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	// defer cancel()

	// setup a git repo
	srvDir := t.TempDir()
	srvFS := osfs.New(srvDir)
	repo := gittest.NewRepo(t, srvFS)
	repo.Commit(gittest.Commit(t, "README.md", "Hello, worldd!", "initial commit"))
	srv := httptest.NewServer(gittest.NewServer(srvFS))

	// clone to a tempdir
	clientDir := t.TempDir()
	clientFS := osfs.New(clientDir)
	cloned, err := git.CloneRepo(ctx, t.Logf, git.CloneRepoOptions{
		Path:    "/repo",
		RepoURL: srv.URL,
		Storage: clientFS,
	})
	require.NoError(t, err)
	require.True(t, cloned)

	// add some commits on the server
	repo.Commit(gittest.Commit(t, "README.md", "Hello, world!", "fix typo"))

	// run CloneRepo again
	clonedAgain, err := git.CloneRepo(ctx, t.Logf, git.CloneRepoOptions{
		Path:    "/repo",
		RepoURL: srv.URL,
		Storage: clientFS,
	})
	require.NoError(t, err)
	require.True(t, clonedAgain)
	contentAfter, err := clientFS.Open("/repo/README.md")
	require.NoError(t, err)
	content, err := io.ReadAll(contentAfter)
	require.NoError(t, err)
	require.Equal(t, "Hello, world!", string(content), "expected client repo to be updated after fetch")
}

func TestCloneRepoSSH(t *testing.T) {
	t.Parallel()

	t.Run("AuthSuccess", func(t *testing.T) {
		t.Parallel()

		// TODO: test the rest of the cloning flow. This just tests successful auth.
		tmpDir := t.TempDir()
		srvFS := osfs.New(tmpDir, osfs.WithChrootOS())

		_ = gittest.NewRepo(t, srvFS).Commit(gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
		key := randKeygen(t)
		tr := gittest.NewServerSSH(t, srvFS, key.PublicKey())
		gitURL := tr.String()
		clientFS := memfs.New()

		cloned, err := git.CloneRepo(context.Background(), t.Logf, git.CloneRepoOptions{
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

		_ = gittest.NewRepo(t, srvFS).Commit(gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
		key := randKeygen(t)
		tr := gittest.NewServerSSH(t, srvFS, key.PublicKey())
		gitURL := tr.String()
		clientFS := memfs.New()

		anotherKey := randKeygen(t)
		cloned, err := git.CloneRepo(context.Background(), t.Logf, git.CloneRepoOptions{
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

		_ = gittest.NewRepo(t, srvFS).Commit(gittest.Commit(t, "README.md", "Hello, world!", "Wow!"))
		key := randKeygen(t)
		tr := gittest.NewServerSSH(t, srvFS, key.PublicKey())
		gitURL := tr.String()
		clientFS := memfs.New()

		cloned, err := git.CloneRepo(context.Background(), t.Logf, git.CloneRepoOptions{
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

// nolint:paralleltest // t.Setenv for SSH_AUTH_SOCK
func TestSetupRepoAuth(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Run("Empty", func(t *testing.T) {
		opts := &options.Options{}
		auth := git.SetupRepoAuth(t.Logf, opts)
		require.Nil(t, auth)
	})

	t.Run("HTTP/NoAuth", func(t *testing.T) {
		opts := &options.Options{
			GitURL: "http://host.tld/repo",
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		require.Nil(t, auth)
	})

	t.Run("HTTP/BasicAuth", func(t *testing.T) {
		opts := &options.Options{
			GitURL:      "http://host.tld/repo",
			GitUsername: "user",
			GitPassword: "pass",
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		ba, ok := auth.(*githttp.BasicAuth)
		require.True(t, ok)
		require.Equal(t, opts.GitUsername, ba.Username)
		require.Equal(t, opts.GitPassword, ba.Password)
	})

	t.Run("HTTPS/BasicAuth", func(t *testing.T) {
		opts := &options.Options{
			GitURL:      "https://host.tld/repo",
			GitUsername: "user",
			GitPassword: "pass",
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		ba, ok := auth.(*githttp.BasicAuth)
		require.True(t, ok)
		require.Equal(t, opts.GitUsername, ba.Username)
		require.Equal(t, opts.GitPassword, ba.Password)
	})

	t.Run("SSH/WithScheme", func(t *testing.T) {
		kPath := writeTestPrivateKey(t)
		opts := &options.Options{
			GitURL:               "ssh://host.tld/repo",
			GitSSHPrivateKeyPath: kPath,
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		_, ok := auth.(*gitssh.PublicKeys)
		require.True(t, ok)
	})

	t.Run("SSH/NoScheme", func(t *testing.T) {
		kPath := writeTestPrivateKey(t)
		opts := &options.Options{
			GitURL:               "git@host.tld:repo/path",
			GitSSHPrivateKeyPath: kPath,
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		_, ok := auth.(*gitssh.PublicKeys)
		require.True(t, ok)
	})

	t.Run("SSH/OtherScheme", func(t *testing.T) {
		// Anything that is not https:// or http:// is treated as SSH.
		kPath := writeTestPrivateKey(t)
		opts := &options.Options{
			GitURL:               "git://git@host.tld:repo/path",
			GitSSHPrivateKeyPath: kPath,
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		_, ok := auth.(*gitssh.PublicKeys)
		require.True(t, ok)
	})

	t.Run("SSH/GitUsername", func(t *testing.T) {
		kPath := writeTestPrivateKey(t)
		opts := &options.Options{
			GitURL:               "host.tld:12345/repo/path",
			GitSSHPrivateKeyPath: kPath,
			GitUsername:          "user",
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		_, ok := auth.(*gitssh.PublicKeys)
		require.True(t, ok)
	})

	t.Run("SSH/PrivateKey", func(t *testing.T) {
		kPath := writeTestPrivateKey(t)
		opts := &options.Options{
			GitURL:               "ssh://git@host.tld:repo/path",
			GitSSHPrivateKeyPath: kPath,
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		pk, ok := auth.(*gitssh.PublicKeys)
		require.True(t, ok)
		require.NotNil(t, pk.Signer)
		actualSigner, err := gossh.ParsePrivateKey([]byte(testKey))
		require.NoError(t, err)
		require.Equal(t, actualSigner, pk.Signer)
	})

	t.Run("SSH/NoAuthMethods", func(t *testing.T) {
		opts := &options.Options{
			GitURL: "ssh://git@host.tld:repo/path",
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		require.Nil(t, auth) // TODO: actually test SSH_AUTH_SOCK
	})

	t.Run("NoHostname/RepoOnly", func(t *testing.T) {
		opts := &options.Options{
			GitURL: "repo",
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		require.Nil(t, auth)
	})

	t.Run("NoHostname/Org/Repo", func(t *testing.T) {
		opts := &options.Options{
			GitURL: "org/repo",
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		require.Nil(t, auth)
	})

	t.Run("NoHostname/AbsolutePathish", func(t *testing.T) {
		opts := &options.Options{
			GitURL: "/org/repo",
		}
		auth := git.SetupRepoAuth(t.Logf, opts)
		require.Nil(t, auth)
	})
}

func mustRead(t *testing.T, fs billy.Filesystem, path string) string {
	t.Helper()
	f, err := fs.OpenFile(path, os.O_RDONLY, 0o644)
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

// nolint:gosec // Throw-away key for testing. DO NOT REUSE.
var testKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBXOGgAge/EbcejqASqZa6s8PFXZle56DiGEt0VYnljuwAAAKgM05mUDNOZ
lAAAAAtzc2gtZWQyNTUxOQAAACBXOGgAge/EbcejqASqZa6s8PFXZle56DiGEt0VYnljuw
AAAEDCawwtjrM4AGYXD1G6uallnbsgMed4cfkFsQ+mLZtOkFc4aACB78Rtx6OoBKplrqzw
8VdmV7noOIYS3RVieWO7AAAAHmNpYW5AY2RyLW1icC1mdmZmdzBuOHEwNXAuaG9tZQECAw
QFBgc=
-----END OPENSSH PRIVATE KEY-----`

func writeTestPrivateKey(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	kPath := filepath.Join(tmpDir, "test.key")
	require.NoError(t, os.WriteFile(kPath, []byte(testKey), 0o600))
	return kPath
}
