package git

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/coder/envbuilder/options"

	giturls "github.com/chainguard-dev/git-urls"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
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
	ThinPack     bool
	Depth        int
	CABundle     []byte
	ProxyOptions transport.ProxyOptions
	SubmoduleDepth int // 0 = disabled, >0 = max recursion depth
}

// CloneRepo will clone the repository at the given URL into the given path.
// If a repository is already initialized at the given path, it will not
// be cloned again.
//
// The bool returned states whether the repository was cloned or not.
func CloneRepo(ctx context.Context, logf func(string, ...any), opts CloneRepoOptions) (bool, error) {
	parsed, err := giturls.Parse(opts.RepoURL)
	if err != nil {
		return false, fmt.Errorf("parse url %q: %w", opts.RepoURL, err)
	}
	logf("Parsed Git URL as %q", parsed.Redacted())

	thinPack := true

	if !opts.ThinPack {
		thinPack = false
		logf("ThinPack options is false, Marking thin-pack as unsupported")
	} else if parsed.Hostname() == "dev.azure.com" {
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
		thinPack = false
		logf("Workaround for Azure DevOps: marking thin-pack as unsupported")
	}

	if !thinPack {
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

	repo, err = git.CloneContext(ctx, gitStorage, fs, &git.CloneOptions{
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

	// Initialize submodules if requested
	if opts.SubmoduleDepth > 0 {
		err = initSubmodules(ctx, logf, repo, opts, 1)
		if err != nil {
			return true, fmt.Errorf("init submodules: %w", err)
		}
	}

	return true, nil
}

// ShallowCloneRepo will clone the repository at the given URL into the given path
// with a depth of 1. If the destination folder exists and is not empty, the
// clone will not be performed.
//
// The bool returned states whether the repository was cloned or not.
func ShallowCloneRepo(ctx context.Context, logf func(string, ...any), opts CloneRepoOptions) error {
	opts.Depth = 1
	opts.SingleBranch = true

	if opts.Path == "" {
		return errors.New("path is required")
	}

	// Avoid clobbering the destination.
	if _, err := opts.Storage.Stat(opts.Path); err == nil {
		files, err := opts.Storage.ReadDir(opts.Path)
		if err != nil {
			return fmt.Errorf("read dir %q: %w", opts.Path, err)
		}
		if len(files) > 0 {
			return fmt.Errorf("directory %q is not empty", opts.Path)
		}
	}

	cloned, err := CloneRepo(ctx, logf, opts)
	if err != nil {
		return err
	}
	if !cloned {
		return errors.New("repository already exists")
	}

	return nil
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

// DecodeBase64PrivateKey attempts to decode a base64 encoded private
// key and returns an ssh.Signer
func DecodeBase64PrivateKey(key string) (gossh.Signer, error) {
	bs, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}

	k, err := gossh.ParsePrivateKey(bs)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return k, nil
}

// LogHostKeyCallback is a HostKeyCallback that just logs host keys
// and does nothing else.
func LogHostKeyCallback(logger func(string, ...any)) gossh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key gossh.PublicKey) error {
		var sb strings.Builder
		_ = knownhosts.WriteKnownHost(&sb, hostname, remote, key)
		// skeema/knownhosts uses a fake public key to determine the host key
		// algorithms. Ignore this one.
		if s := sb.String(); !strings.Contains(s, "fake-public-key ZmFrZSBwdWJsaWMga2V5") {
			logger("🔑 Got host key: %s", strings.TrimSpace(s))
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
// | file://path/to/repo     | -            | -            | None        |
// | path/to/repo            | -            | -            | None        |
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
func SetupRepoAuth(logf func(string, ...any), options *options.Options) transport.AuthMethod {
	if options.GitURL == "" {
		logf("❔ No Git URL supplied!")
		return nil
	}
	parsedURL, err := giturls.Parse(options.GitURL)
	if err != nil {
		logf("❌ Failed to parse Git URL: %s", err.Error())
		return nil
	}

	if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
		// Special case: no auth
		if options.GitUsername == "" && options.GitPassword == "" {
			logf("👤 Using no authentication!")
			return nil
		}
		// Basic Auth
		// NOTE: we previously inserted the credentials into the repo URL.
		// This was removed in https://github.com/coder/envbuilder/pull/141
		logf("🔒 Using HTTP basic authentication!")
		return &githttp.BasicAuth{
			Username: options.GitUsername,
			Password: options.GitPassword,
		}
	}

	if parsedURL.Scheme == "file" {
		// go-git will try to fallback to using the `git` command for local
		// filesystem clones. However, it's more likely than not that the
		// `git` command is not present in the container image. Log a warning
		// but continue. Also, no auth.
		logf("🚧 Using local filesystem clone! This requires the git executable to be present!")
		return nil
	}

	// Generally git clones over SSH use the 'git' user, but respect
	// GIT_USERNAME if set.
	if options.GitUsername == "" {
		options.GitUsername = "git"
	}

	// Assume SSH auth for all other formats.
	logf("🔑 Using SSH authentication!")

	var signer ssh.Signer
	if options.GitSSHPrivateKeyPath != "" {
		s, err := ReadPrivateKey(options.GitSSHPrivateKeyPath)
		if err != nil {
			logf("❌ Failed to read private key from %s: %s", options.GitSSHPrivateKeyPath, err.Error())
		} else {
			logf("🔑 Using %s key!", s.PublicKey().Type())
			signer = s
		}
	}

	// If no path was provided, fall back to the environment variable
	if options.GitSSHPrivateKeyBase64 != "" {
		s, err := DecodeBase64PrivateKey(options.GitSSHPrivateKeyBase64)
		if err != nil {
			logf("❌ Failed to decode base 64 private key: %s", err.Error())
		} else {
			logf("🔑 Using %s key!", s.PublicKey().Type())
			signer = s
		}
	}

	// If no SSH key set, fall back to agent auth.
	if signer == nil {
		logf("🔑 No SSH key found, falling back to agent!")
		auth, err := gitssh.NewSSHAgentAuth(options.GitUsername)
		if err != nil {
			logf("❌ Failed to connect to SSH agent: " + err.Error())
			return nil // nothing else we can do
		}
		if os.Getenv("SSH_KNOWN_HOSTS") == "" {
			logf("🔓 SSH_KNOWN_HOSTS not set, accepting all host keys!")
			auth.HostKeyCallback = LogHostKeyCallback(logf)
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
		logf("🔓 SSH_KNOWN_HOSTS not set, accepting all host keys!")
		auth.HostKeyCallback = LogHostKeyCallback(logf)
	}
	return auth
}

func CloneOptionsFromOptions(logf func(string, ...any), options options.Options) (CloneRepoOptions, error) {
	caBundle, err := options.CABundle()
	if err != nil {
		return CloneRepoOptions{}, err
	}

	cloneOpts := CloneRepoOptions{
		RepoURL:      options.GitURL,
		Path:         options.WorkspaceFolder,
		Storage:      options.Filesystem,
		Insecure:     options.Insecure,
		SingleBranch: options.GitCloneSingleBranch,
		ThinPack:     options.GitCloneThinPack,
		Depth:        int(options.GitCloneDepth),
		CABundle:     caBundle,
		SubmoduleDepth: options.GitCloneSubmodules,
	}

	cloneOpts.RepoAuth = SetupRepoAuth(logf, &options)
	if options.GitHTTPProxyURL != "" {
		cloneOpts.ProxyOptions = transport.ProxyOptions{
			URL: options.GitHTTPProxyURL,
		}
	}

	return cloneOpts, nil
}

type progressWriter struct {
	io.WriteCloser
	r    io.ReadCloser
	done chan struct{}
}

func (w *progressWriter) Close() error {
	err := w.WriteCloser.Close()
	<-w.done
	err2 := w.r.Close()
	if err != nil {
		return err
	}
	return err2
}

func ProgressWriter(write func(line string, args ...any)) io.WriteCloser {
	reader, writer := io.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		data := make([]byte, 4096)
		for {
			read, err := reader.Read(data)
			if err != nil {
				return
			}
			content := data[:read]
			for _, line := range strings.Split(string(content), "\r") {
				if line == "" {
					continue
				}
				// Escape % signs so that they don't get interpreted as format specifiers
				line = strings.Replace(line, "%", "%%", -1)
				write(strings.TrimSpace(line))
			}
		}
	}()

	return &progressWriter{
		WriteCloser: writer,
		r:           reader,
		done:        done,
	}
}

// resolveSubmoduleURL resolves a potentially relative submodule URL against the parent repository URL
// ResolveSubmoduleURL resolves a potentially relative submodule URL against a parent repository URL.
func ResolveSubmoduleURL(parentURL, submoduleURL string) (string, error) {
	// If the submodule URL is absolute (contains ://) or doesn't start with ./ or ../, return it as-is
	if strings.Contains(submoduleURL, "://") || (!strings.HasPrefix(submoduleURL, "../") && !strings.HasPrefix(submoduleURL, "./")) {
		return submoduleURL, nil
	}

	// Parse the parent URL
	parentParsed, err := url.Parse(parentURL)
	if err != nil {
		return "", fmt.Errorf("parse parent URL: %w", err)
	}

	// For relative URLs, we need to resolve them against the parent's path
	// The parent path represents a repository (like a file in filesystem terms)
	// So ../something means "sibling repository"
	parentPath := strings.TrimSuffix(parentParsed.Path, "/")

	// Split the submodule URL into components
	// and manually walk up the directory tree for each ../
	currentPath := parentPath
	relativeParts := strings.Split(submoduleURL, "/")

	for _, part := range relativeParts {
		if part == ".." {
			// Go up one directory
			currentPath = path.Dir(currentPath)
		} else if part == "." {
			// Stay in current directory
			continue
		} else if part != "" {
			// Add this component to the path
			currentPath = currentPath + "/" + part
		}
	}

	// Clean the final path
	resolvedPath := path.Clean(currentPath)

	// Construct the absolute URL
	resolvedParsed := &url.URL{
		Scheme: parentParsed.Scheme,
		User:   parentParsed.User,
		Host:   parentParsed.Host,
		Path:   resolvedPath,
	}

	return resolvedParsed.String(), nil
}

// initSubmodules recursively initializes and updates all submodules in the repository.
// currentDepth tracks the current recursion level (starts at 1).
func initSubmodules(ctx context.Context, logf func(string, ...any), repo *git.Repository, opts CloneRepoOptions, currentDepth int) error {
	if currentDepth > opts.SubmoduleDepth {
		logf("⚠ Skipping nested submodules: max depth %d reached", opts.SubmoduleDepth)
		return nil
	}
	logf("🔗 Initializing git submodules (depth %d/%d)...", currentDepth, opts.SubmoduleDepth)

	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("get worktree: %w", err)
	}

	subs, err := w.Submodules()
	if err != nil {
		return fmt.Errorf("get submodules: %w", err)
	}

	if len(subs) == 0 {
		logf("No submodules found")
		return nil
	}

	logf("Found %d submodule(s)", len(subs))

	// Get the parent repository URL for resolving relative submodule URLs
	cfg, err := repo.Config()
	if err != nil {
		return fmt.Errorf("get repo config: %w", err)
	}

	parentURL := opts.RepoURL
	if origin, hasOrigin := cfg.Remotes["origin"]; hasOrigin && len(origin.URLs) > 0 {
		parentURL = origin.URLs[0]
	}
	logf("Parent repository URL: %s", parentURL)

	for _, sub := range subs {
		subConfig := sub.Config()
		logf("📦 Initializing submodule: %s", subConfig.Name)
		logf("  Submodule path: %s", subConfig.Path)
		logf("  Submodule URL (from .gitmodules): %s", subConfig.URL)

		// Get the expected commit hash
		subStatus, err := sub.Status()
		if err != nil {
			return fmt.Errorf("get submodule status for %q: %w", subConfig.Name, err)
		}
		logf("  Expected commit: %s", subStatus.Expected)

		// Resolve the submodule URL
		resolvedURL, err := ResolveSubmoduleURL(parentURL, subConfig.URL)
		if err != nil {
			return fmt.Errorf("resolve submodule URL for %q: %w", subConfig.Name, err)
		}
		logf("  Resolved URL: %s", resolvedURL)

		// Clone the submodule manually
		err = cloneSubmodule(ctx, logf, w, subConfig, subStatus.Expected, resolvedURL, opts)
		if err != nil {
			return fmt.Errorf("clone submodule %q: %w", subConfig.Name, err)
		}

		logf("✓ Submodule initialized: %s", subConfig.Name)

		// Recursively handle nested submodules
		subRepo, err := sub.Repository()
		if err != nil {
			logf("  ⚠ Could not open submodule repository %s: %v", subConfig.Name, err)
			continue
		}

		// Check for nested submodules
		subWorktree, err := subRepo.Worktree()
		if err == nil {
			nestedSubs, err := subWorktree.Submodules()
			if err == nil && len(nestedSubs) > 0 {
				logf("  Found %d nested submodule(s) in %s", len(nestedSubs), subConfig.Name)
				// Create new opts with the submodule's URL as the parent
				nestedOpts := opts
				nestedOpts.RepoURL = resolvedURL
				err = initSubmodules(ctx, logf, subRepo, nestedOpts, currentDepth+1)
				if err != nil {
					return fmt.Errorf("init nested submodules in %q: %w", subConfig.Name, err)
				}
			}
		}
	}

	logf("✓ All submodules initialized successfully")
	return nil
}

// cloneSubmodule manually clones a submodule repository
func cloneSubmodule(ctx context.Context, logf func(string, ...any), parentWorktree *git.Worktree, subConfig *config.Submodule, expectedHash plumbing.Hash, resolvedURL string, opts CloneRepoOptions) error {
	// Get the submodule directory within the parent worktree
	submodulePath := subConfig.Path

	// Create the submodule directory
	subFS, err := parentWorktree.Filesystem.Chroot(submodulePath)
	if err != nil {
		return fmt.Errorf("chroot to submodule path: %w", err)
	}

	// Check if already cloned
	_, err = subFS.Stat(".git")
	if err == nil {
		logf("  Submodule already cloned, checking out expected commit...")
		// Open the existing repository
		subRepo, err := git.Open(
			filesystem.NewStorage(subFS, cache.NewObjectLRU(cache.DefaultMaxSize)),
			subFS,
		)
		if err != nil {
			return fmt.Errorf("open existing submodule: %w", err)
		}

		subWorktree, err := subRepo.Worktree()
		if err != nil {
			return fmt.Errorf("get submodule worktree: %w", err)
		}

		// Checkout the expected commit
		err = subWorktree.Checkout(&git.CheckoutOptions{
			Hash: expectedHash,
		})
		if err != nil {
			return fmt.Errorf("checkout expected commit: %w", err)
		}
		return nil
	}

	// Clone the submodule
	logf("  Cloning submodule from: %s", resolvedURL)

	// Create .git directory for the submodule
	err = subFS.MkdirAll(".git", 0o755)
	if err != nil {
		return fmt.Errorf("create .git directory: %w", err)
	}

	subGitDir, err := subFS.Chroot(".git")
	if err != nil {
		return fmt.Errorf("chroot to .git: %w", err)
	}

	gitStorage := filesystem.NewStorage(subGitDir, cache.NewObjectLRU(cache.DefaultMaxSize*10))

	// Clone the submodule repository
	// Use SingleBranch=false to fetch all branches so we can find the commit
	subRepo, err := git.CloneContext(ctx, gitStorage, subFS, &git.CloneOptions{
		URL:             resolvedURL,
		Auth:            opts.RepoAuth,
		Progress:        opts.Progress,
		InsecureSkipTLS: opts.Insecure,
		CABundle:        opts.CABundle,
		ProxyOptions:    opts.ProxyOptions,
		SingleBranch:    false, // Fetch all branches
		NoCheckout:      true,  // Don't checkout yet, we'll do it manually
	})
	if err != nil && !errors.Is(err, git.ErrRepositoryAlreadyExists) {
		return fmt.Errorf("clone submodule repository: %w", err)
	}

	// Verify the commit exists
	logf("  Verifying commit exists: %s", expectedHash)
	_, err = subRepo.CommitObject(expectedHash)
	if err != nil {
		// Commit not found, try fetching with the specific hash
		logf("  Commit not found, attempting to fetch it directly...")
		err = subRepo.FetchContext(ctx, &git.FetchOptions{
			RemoteName: "origin",
			RefSpecs: []config.RefSpec{
				config.RefSpec("+" + expectedHash.String() + ":" + expectedHash.String()),
			},
			Auth:            opts.RepoAuth,
			Progress:        opts.Progress,
			InsecureSkipTLS: opts.Insecure,
			CABundle:        opts.CABundle,
			ProxyOptions:    opts.ProxyOptions,
		})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			// If that fails, try fetching all refs
			logf("  Direct fetch failed, fetching all refs...")
			err = subRepo.FetchContext(ctx, &git.FetchOptions{
				RemoteName:      "origin",
				Auth:            opts.RepoAuth,
				Progress:        opts.Progress,
				InsecureSkipTLS: opts.Insecure,
				CABundle:        opts.CABundle,
				ProxyOptions:    opts.ProxyOptions,
			})
			if err != nil && err != git.NoErrAlreadyUpToDate {
				return fmt.Errorf("fetch commit %s: %w", expectedHash, err)
			}
		}

		// Verify again
		_, err = subRepo.CommitObject(expectedHash)
		if err != nil {
			return fmt.Errorf("commit %s still not found after fetch: %w", expectedHash, err)
		}
	}

	// Checkout the specific commit expected by the parent repository
	logf("  Checking out commit: %s", expectedHash)
	subWorktree, err := subRepo.Worktree()
	if err != nil {
		return fmt.Errorf("get submodule worktree: %w", err)
	}

	err = subWorktree.Checkout(&git.CheckoutOptions{
		Hash: expectedHash,
	})
	if err != nil {
		return fmt.Errorf("checkout expected commit %s: %w", expectedHash, err)
	}

	return nil
}
