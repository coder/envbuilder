package envbuilder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	giturls "github.com/chainguard-dev/git-urls"
	"github.com/coder/envbuilder/internal/notcodersdk"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
	gossh "golang.org/x/crypto/ssh"
)

type CloneRepoOptions struct {
	Path    string
	Storage billy.Filesystem

	RepoURL      string
	RepoAuth     transport.AuthMethod
	Progress     sideband.Progress
	Insecure     bool
	SingleBranch bool
	Depth        int
	CABundle     []byte
	ProxyOptions transport.ProxyOptions
}

// CloneRepo will clone the repository at the given URL into the given path.
// If a repository is already initialized at the given path, it will not
// be cloned again.
//
// The bool returned states whether the repository was cloned or not.
func CloneRepo(ctx context.Context, opts CloneRepoOptions) (bool, error) {
	parsed, err := giturls.Parse(opts.RepoURL)
	if err != nil {
		return false, fmt.Errorf("parse url %q: %w", opts.RepoURL, err)
	}
	if parsed.Hostname() == "dev.azure.com" {
		// Azure DevOps requires capabilities multi_ack / multi_ack_detailed,
		// which are not fully implemented and by default are included in
		// transport.UnsupportedCapabilities.
		//
		// The initial clone operations require a full download of the repository,
		// and therefore those unsupported capabilities are not as crucial, so
		// by removing them from that list allows for the first clone to work
		// successfully.
		//
		// Additional fetches will yield issues, therefore work always from a clean
		// clone until those capabilities are fully supported.
		//
		// New commits and pushes against a remote worked without any issues.
		// See: https://github.com/go-git/go-git/issues/64
		//
		// This is knowingly not safe to call in parallel, but it seemed
		// like the least-janky place to add a super janky hack.
		transport.UnsupportedCapabilities = []capability.Capability{
			capability.ThinPack,
		}
	}

	err = opts.Storage.MkdirAll(opts.Path, 0o755)
	if err != nil {
		return false, fmt.Errorf("mkdir %q: %w", opts.Path, err)
	}
	reference := parsed.Fragment
	if reference == "" && opts.SingleBranch {
		reference = "refs/heads/main"
	}
	parsed.RawFragment = ""
	parsed.Fragment = ""
	fs, err := opts.Storage.Chroot(opts.Path)
	if err != nil {
		return false, fmt.Errorf("chroot %q: %w", opts.Path, err)
	}
	gitDir, err := fs.Chroot(".git")
	if err != nil {
		return false, fmt.Errorf("chroot .git: %w", err)
	}
	gitStorage := filesystem.NewStorage(gitDir, cache.NewObjectLRU(cache.DefaultMaxSize*10))
	fsStorage := filesystem.NewStorage(fs, cache.NewObjectLRU(cache.DefaultMaxSize*10))
	repo, err := git.Open(fsStorage, gitDir)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		err = nil
	}
	if err != nil {
		return false, fmt.Errorf("open %q: %w", opts.RepoURL, err)
	}
	if repo != nil {
		return false, nil
	}

	_, err = git.CloneContext(ctx, gitStorage, fs, &git.CloneOptions{
		URL:             parsed.String(),
		Auth:            opts.RepoAuth,
		Progress:        opts.Progress,
		ReferenceName:   plumbing.ReferenceName(reference),
		InsecureSkipTLS: opts.Insecure,
		Depth:           opts.Depth,
		SingleBranch:    opts.SingleBranch,
		CABundle:        opts.CABundle,
		ProxyOptions:    opts.ProxyOptions,
	})
	if errors.Is(err, git.ErrRepositoryAlreadyExists) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("clone %q: %w", opts.RepoURL, err)
	}
	return true, nil
}

// ReadPrivateKey attempts to read an SSH private key from path
// and returns an ssh.Signer.
func ReadPrivateKey(path string) (gossh.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open private key file: %w", err)
	}
	defer f.Close()
	bs, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}
	k, err := gossh.ParsePrivateKey(bs)
	if err != nil {
		return nil, fmt.Errorf("parse private key file: %w", err)
	}
	return k, nil
}

// LogHostKeyCallback is a HostKeyCallback that just logs host keys
// and does nothing else.
func LogHostKeyCallback(log LoggerFunc) gossh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		var sb strings.Builder
		_ = knownhosts.WriteKnownHost(&sb, hostname, remote, key)
		// skeema/knownhosts uses a fake public key to determine the host key
		// algorithms. Ignore this one.
		if s := sb.String(); !strings.Contains(s, "fake-public-key ZmFrZSBwdWJsaWMga2V5") {
			log(notcodersdk.LogLevelInfo, "#1: 🔑 Got host key: %s", strings.TrimSpace(s))
		}
		return nil
	}
}

// SetupRepoAuth determines the desired AuthMethod based on options.GitURL:
//
// | Git URL format          | GIT_USERNAME | GIT_PASSWORD | Auth Method |
// | ------------------------|--------------|--------------|-------------|
// | https?://host.tld/repo  | Not Set      | Not Set      | None        |
// | https?://host.tld/repo  | Not Set      | Set          | HTTP Basic  |
// | https?://host.tld/repo  | Set          | Not Set      | HTTP Basic  |
// | https?://host.tld/repo  | Set          | Set          | HTTP Basic  |
// | All other formats       | -            | -            | SSH         |
//
// For SSH authentication, the default username is "git" but will honour
// GIT_USERNAME if set.
//
// If SSH_PRIVATE_KEY_PATH is set, an SSH private key will be read from
// that path and the SSH auth method will be configured with that key.
//
// If SSH_KNOWN_HOSTS is not set, the SSH auth method will be configured
// to accept and log all host keys. Otherwise, host key checking will be
// performed as usual.
func SetupRepoAuth(options *Options) transport.AuthMethod {
	if options.GitURL == "" {
		options.Logger(notcodersdk.LogLevelInfo, "#1: ❔ No Git URL supplied!")
		return nil
	}
	if strings.HasPrefix(options.GitURL, "http://") || strings.HasPrefix(options.GitURL, "https://") {
		// Special case: no auth
		if options.GitUsername == "" && options.GitPassword == "" {
			options.Logger(notcodersdk.LogLevelInfo, "#1: 👤 Using no authentication!")
			return nil
		}
		// Basic Auth
		// NOTE: we previously inserted the credentials into the repo URL.
		// This was removed in https://github.com/coder/envbuilder/pull/141
		options.Logger(notcodersdk.LogLevelInfo, "#1: 🔒 Using HTTP basic authentication!")
		return &githttp.BasicAuth{
			Username: options.GitUsername,
			Password: options.GitPassword,
		}
	}

	// Generally git clones over SSH use the 'git' user, but respect
	// GIT_USERNAME if set.
	if options.GitUsername == "" {
		options.GitUsername = "git"
	}

	// Assume SSH auth for all other formats.
	options.Logger(notcodersdk.LogLevelInfo, "#1: 🔑 Using SSH authentication!")

	var signer ssh.Signer
	if options.GitSSHPrivateKeyPath != "" {
		s, err := ReadPrivateKey(options.GitSSHPrivateKeyPath)
		if err != nil {
			options.Logger(notcodersdk.LogLevelError, "#1: ❌ Failed to read private key from %s: %s", options.GitSSHPrivateKeyPath, err.Error())
		} else {
			options.Logger(notcodersdk.LogLevelInfo, "#1: 🔑 Using %s key!", s.PublicKey().Type())
			signer = s
		}
	}

	// If no SSH key set, fall back to agent auth.
	if signer == nil {
		options.Logger(notcodersdk.LogLevelError, "#1: 🔑 No SSH key found, falling back to agent!")
		auth, err := gitssh.NewSSHAgentAuth(options.GitUsername)
		if err != nil {
			options.Logger(notcodersdk.LogLevelError, "#1: ❌ Failed to connect to SSH agent: %s", err.Error())
			return nil // nothing else we can do
		}
		if os.Getenv("SSH_KNOWN_HOSTS") == "" {
			options.Logger(notcodersdk.LogLevelWarn, "#1: 🔓 SSH_KNOWN_HOSTS not set, accepting all host keys!")
			auth.HostKeyCallback = LogHostKeyCallback(options.Logger)
		}
		return auth
	}

	auth := &gitssh.PublicKeys{
		User:   options.GitUsername,
		Signer: signer,
	}

	// Generally git clones over SSH use the 'git' user, but respect
	// GIT_USERNAME if set.
	if auth.User == "" {
		auth.User = "git"
	}

	// Duplicated code due to Go's type system.
	if os.Getenv("SSH_KNOWN_HOSTS") == "" {
		options.Logger(notcodersdk.LogLevelWarn, "#1: 🔓 SSH_KNOWN_HOSTS not set, accepting all host keys!")
		auth.HostKeyCallback = LogHostKeyCallback(options.Logger)
	}
	return auth
}
