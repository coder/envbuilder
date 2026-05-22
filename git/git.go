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
	"regexp"
	"strings"

	"github.com/coder/envbuilder/internal/ebutil"
	"github.com/coder/envbuilder/options"

	"github.com/go-git/go-billy/v5"
	billyutil "github.com/go-git/go-billy/v5/util"
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

	RepoURL        string
	RepoAuth       transport.AuthMethod
	Progress       sideband.Progress
	Insecure       bool
	SingleBranch   bool
	ThinPack       bool
	Depth          int
	CABundle       []byte
	ProxyOptions   transport.ProxyOptions
	SubmoduleDepth int // 0 = disabled, >0 = max recursion depth
}

// CloneRepo will clone the repository at the given URL into the given path.
// If a repository is already initialized at the given path, it will not
// be cloned again.
//
// The bool returned states whether the repository was cloned or not.
func CloneRepo(ctx context.Context, logf func(string, ...any), opts CloneRepoOptions) (bool, error) {
	parsed, err := ebutil.ParseRepoURL(opts.RepoURL)
	if err != nil {
		return false, fmt.Errorf("parse url %q: %w", opts.RepoURL, err)
	}

	thinPack := true

	if !opts.ThinPack {
		thinPack = false
		logf("ThinPack options is false, Marking thin-pack as unsupported")
	} else if parsed.Host == "dev.azure.com" {
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
	if parsed.Reference == "" && opts.SingleBranch {
		parsed.Reference = "refs/heads/main"
	}
	fs, err := opts.Storage.Chroot(opts.Path)
	if err != nil {
		return false, fmt.Errorf("chroot %q: %w", opts.Path, err)
	}
	gitDir, err := fs.Chroot(".git")
	if err != nil {
		return false, fmt.Errorf("chroot .git: %w", err)
	}
	gitStorage := filesystem.NewStorage(gitDir, cache.NewObjectLRU(cache.DefaultMaxSize*10))
	repo, err := git.Open(gitStorage, fs)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		err = nil
	}
	if err != nil {
		return false, fmt.Errorf("open %q: %w", opts.RepoURL, err)
	}

	alreadyCloned := repo != nil
	if !alreadyCloned {
		repo, err = git.CloneContext(ctx, gitStorage, fs, &git.CloneOptions{
			URL:             parsed.Cleaned,
			Auth:            opts.RepoAuth,
			Progress:        opts.Progress,
			ReferenceName:   plumbing.ReferenceName(parsed.Reference),
			InsecureSkipTLS: opts.Insecure,
			Depth:           opts.Depth,
			SingleBranch:    opts.SingleBranch,
			CABundle:        opts.CABundle,
			ProxyOptions:    opts.ProxyOptions,
		})
		if errors.Is(err, git.ErrRepositoryAlreadyExists) {
			// The repository was created between our Open and CloneContext
			// calls. Reopen it so submodule initialization can still run.
			repo, err = git.Open(gitStorage, fs)
			if err != nil {
				return false, fmt.Errorf("reopen existing %q: %w", opts.RepoURL, err)
			}
			alreadyCloned = true
		}
		if err != nil {
			return false, fmt.Errorf("clone %q: %w", opts.RepoURL, err)
		}
	}

	// Initialize submodules on every call, not only after a fresh clone, so
	// that a transient failure during the first run can be retried on the
	// next workspace start.
	if opts.SubmoduleDepth > 0 {
		w, err := repo.Worktree()
		if err != nil {
			return !alreadyCloned, fmt.Errorf("get worktree: %w", err)
		}
		if err := initSubmodules(ctx, logf, repo, w, opts.RepoURL, opts.RepoAuth, opts, 1); err != nil {
			return !alreadyCloned, fmt.Errorf("init submodules: %w", err)
		}
	}

	return !alreadyCloned, nil
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
//
// Git URL formats may only consist of the following:
//  1. A valid URL with a scheme
//  2. An SCP-like URL (e.g. git@host.tld:path/to/repo.git)
//  3. Local filesystem paths (require `git` executable)
func SetupRepoAuth(logf func(string, ...any), options *options.Options) transport.AuthMethod {
	if options.GitURL == "" {
		logf("❔ No Git URL supplied!")
		return nil
	}
	parsedURL, err := ebutil.ParseRepoURL(options.GitURL)
	if err != nil {
		logf("❌ Failed to parse Git URL: %s", err.Error())
		return nil
	}

	if parsedURL.Protocol == "http" || parsedURL.Protocol == "https" {
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

	if parsedURL.Protocol == "file" {
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
		RepoURL:        options.GitURL,
		Path:           options.WorkspaceFolder,
		Storage:        options.Filesystem,
		Insecure:       options.Insecure,
		SingleBranch:   options.GitCloneSingleBranch,
		ThinPack:       options.GitCloneThinPack,
		Depth:          int(options.GitCloneDepth),
		CABundle:       caBundle,
		SubmoduleDepth: options.GitCloneSubmoduleDepth,
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

// scpLikeURLRegex matches SCP-like URLs: user@host:path (where host is not empty and path doesn't start with /)
// This handles: git@github.com:org/repo, deploy@host:repo, user@10.0.0.5:project
var scpLikeURLRegex = regexp.MustCompile(`^([^@]+)@([^:]+):(.+)$`)

// extractHost extracts the host from a URL, handling both standard URLs and SCP-like URLs.
// Returns empty string if host cannot be determined.
func extractHost(u string) string {
	ep, err := transport.NewEndpoint(u)
	if err != nil || ep.Host == "" {
		return ""
	}
	return strings.ToLower(ep.Host)
}

// SameHost checks if two URLs point to the same host.
// Used to determine if credentials should be forwarded to submodules.
// The comparison is hostname-only. Port is ignored as a simplification;
// submodules on the same host at different ports are uncommon.
func SameHost(url1, url2 string) bool {
	host1 := extractHost(url1)
	host2 := extractHost(url2)
	return host1 != "" && host2 != "" && host1 == host2
}

// RedactURL redacts credentials from a URL for safe logging.
// Handles:
//   - Standard URLs with userinfo: https://user:pass@host, https://token@host
//   - URL-encoded credentials: https://user:p%40ss@host
//   - SCP-like URLs: git@host:path, deploy@host:path, user@10.0.0.5:path
//   - Various schemes: http, https, ssh, git, ftp, sftp
//   - IPv6 hosts: https://user@[2001:db8::1]/path
func RedactURL(u string) string {
	// Try to parse as a standard URL first (handles schemes like https://, ssh://, etc.)
	parsed, err := url.Parse(u)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		// Successfully parsed as a URL with a scheme and host
		// Redact userinfo if present (handles user, user:pass, token, URL-encoded creds)
		if parsed.User != nil {
			// Build URL manually to avoid url.User encoding *** as %2A%2A%2A
			result := parsed.Scheme + "://***@" + parsed.Host + parsed.Path
			if parsed.RawQuery != "" {
				result += "?" + parsed.RawQuery
			}
			if parsed.Fragment != "" {
				result += "#" + parsed.Fragment
			}
			return result
		}
		return parsed.String()
	}

	// Handle SCP-like URLs: user@host:path (no scheme)
	// Only check this if url.Parse didn't find a valid scheme+host
	// (to avoid matching URLs like https://user@[ipv6]:path)
	// This catches: git@github.com:org/repo, deploy@host:repo, oauth2:token@gitlab.com:org/repo
	if matches := scpLikeURLRegex.FindStringSubmatch(u); matches != nil {
		// matches[1] = user part (could be git, deploy, oauth2:token, etc.)
		// matches[2] = host
		// matches[3] = path
		return "***@" + matches[2] + ":" + matches[3]
	}

	// If we can't parse it and it's not SCP-like, return as-is
	// (probably not a URL with credentials)
	return u
}

// ResolveSubmoduleURL resolves a potentially relative submodule URL against a parent repository URL.
func ResolveSubmoduleURL(parentURL, submoduleURL string) (string, error) {
	// If the submodule URL is absolute (contains ://) or doesn't start with ./ or ../, return it as-is
	if strings.Contains(submoduleURL, "://") || (!strings.HasPrefix(submoduleURL, "../") && !strings.HasPrefix(submoduleURL, "./")) {
		return submoduleURL, nil
	}

	// Parse the parent URL using go-git's endpoint parser, which handles
	// SCP-like URLs (git@host:path) in addition to standard URLs.
	parentEP, err := transport.NewEndpoint(parentURL)
	if err != nil {
		return "", fmt.Errorf("parse parent URL: %w", err)
	}

	// Credentials embedded in the parent URL must not leak into resolved
	// submodule URLs. They should flow only through CloneRepoOptions.RepoAuth,
	// which is gated by SameHost. For ssh:// endpoints the user portion is
	// the SSH login name rather than a credential, so it is preserved.
	parentEP.Password = ""
	if !strings.EqualFold(parentEP.Protocol, "ssh") {
		parentEP.User = ""
	}

	// For relative URLs, we need to resolve them against the parent's path.
	// The parent path represents a repository (like a file in filesystem terms),
	// so ../something means "sibling repository".
	parentPath := strings.TrimSuffix(parentEP.Path, "/")

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

	// Reconstruct the URL with the resolved path.
	parentEP.Path = path.Clean(currentPath)
	return parentEP.String(), nil
}

// initSubmodules recursively initializes and updates the submodules of repo.
// currentDepth tracks the current recursion level, starting at 1. parentAuth
// is the auth that was actually used to fetch the current parent. It must be
// the auth for this level, not the root auth, so that a credential withheld
// at any point in the chain stays withheld for every level below it.
func initSubmodules(ctx context.Context, logf func(string, ...any), repo *git.Repository, parentWorktree *git.Worktree, parentURL string, parentAuth transport.AuthMethod, opts CloneRepoOptions, currentDepth int) error {
	if currentDepth > opts.SubmoduleDepth {
		logf("⚠ Skipping nested submodules: max depth %d reached", opts.SubmoduleDepth)
		return nil
	}
	logf("🔗 Initializing git submodules (depth %d/%d)...", currentDepth, opts.SubmoduleDepth)

	subs, err := parentWorktree.Submodules()
	if err != nil {
		return fmt.Errorf("get submodules: %w", err)
	}

	if len(subs) == 0 {
		logf("No submodules found")
		return nil
	}

	logf("Found %d submodule(s)", len(subs))

	// Get the parent repository URL for resolving relative submodule URLs
	effectiveParentURL := parentURL
	if cfg, cfgErr := repo.Config(); cfgErr == nil {
		if origin, ok := cfg.Remotes["origin"]; ok && len(origin.URLs) > 0 {
			effectiveParentURL = origin.URLs[0]
		}
	}
	logf("Parent repository URL: %s", RedactURL(effectiveParentURL))

	var warnings int
	for _, sub := range subs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		subConfig := sub.Config()
		logf("📦 Initializing submodule: %s", subConfig.Name)
		logf("  Submodule path: %s", subConfig.Path)
		logf("  Submodule URL (from .gitmodules): %s", RedactURL(subConfig.URL))

		// Get the expected commit hash
		subStatus, err := sub.Status()
		if err != nil {
			return fmt.Errorf("get submodule status for %q: %w", subConfig.Name, err)
		}
		logf("  Expected commit: %s", subStatus.Expected)

		// Resolve the submodule URL
		resolvedURL, err := ResolveSubmoduleURL(effectiveParentURL, subConfig.URL)
		if err != nil {
			return fmt.Errorf("resolve submodule URL for %q: %w", subConfig.Name, err)
		}
		logf("  Resolved URL: %s", RedactURL(resolvedURL))

		submoduleAuth := submoduleAuthFor(logf, effectiveParentURL, resolvedURL, parentAuth)

		// Clone the submodule manually
		if err := cloneSubmodule(ctx, logf, parentWorktree, subConfig, subStatus.Expected, resolvedURL, submoduleAuth, opts); err != nil {
			return fmt.Errorf("clone submodule %q: %w", subConfig.Name, err)
		}

		logf("✓ Submodule initialized: %s", subConfig.Name)

		// Recurse into any nested submodules. We open the on-disk repository
		// directly rather than calling sub.Repository(), which requires the
		// submodule to be registered in .git/config via sub.Init(). The custom
		// clone path does not perform that registration.
		if currentDepth >= opts.SubmoduleDepth {
			continue
		}
		subRepo, subWorktree, err := openSubmoduleRepo(parentWorktree, subConfig.Path)
		if err != nil {
			logf("  ⚠ Could not open submodule repository %s for nested traversal: %v", subConfig.Name, err)
			warnings++
			continue
		}
		nestedSubs, err := subWorktree.Submodules()
		if err != nil {
			logf("  ⚠ Could not list nested submodules in %s: %v", subConfig.Name, err)
			warnings++
			continue
		}
		if len(nestedSubs) == 0 {
			continue
		}
		logf("  Found %d nested submodule(s) in %s", len(nestedSubs), subConfig.Name)
		if err := initSubmodules(ctx, logf, subRepo, subWorktree, resolvedURL, submoduleAuth, opts, currentDepth+1); err != nil {
			return fmt.Errorf("init nested submodules in %q: %w", subConfig.Name, err)
		}
	}

	if warnings > 0 {
		logf("⚠ Submodule initialization finished with %d warning(s)", warnings)
	} else {
		logf("✓ All submodules initialized successfully")
	}
	return nil
}

// submoduleAuthFor returns the auth to use when fetching a submodule. It
// returns parentAuth if the submodule shares the parent's host, and nil
// otherwise. A warning is logged when parent auth is set but withheld
// because the hosts differ.
//
// The check is host-only and does not compare transport protocols. If
// the parent uses SSH auth and a submodule on the same host uses HTTPS,
// the SSH auth is forwarded and go-git rejects it at the transport
// layer. This is intentional: returning nil here would silently skip
// auth for a submodule that legitimately needs it under a different
// protocol.
func submoduleAuthFor(logf func(string, ...any), parentURL, submoduleURL string, parentAuth transport.AuthMethod) transport.AuthMethod {
	if parentAuth == nil {
		return nil
	}
	if SameHost(parentURL, submoduleURL) {
		return parentAuth
	}
	logf("  ⚠ Not forwarding auth to submodule (different host: %s)", extractHost(submoduleURL))
	return nil
}

// openSubmoduleRepo opens the on-disk repository written by cloneSubmodule
// at parentWorktree/submodulePath/.git and returns it along with its worktree.
func openSubmoduleRepo(parentWorktree *git.Worktree, submodulePath string) (*git.Repository, *git.Worktree, error) {
	subFS, err := parentWorktree.Filesystem.Chroot(submodulePath)
	if err != nil {
		return nil, nil, fmt.Errorf("chroot to submodule path: %w", err)
	}
	subGitDir, err := subFS.Chroot(".git")
	if err != nil {
		return nil, nil, fmt.Errorf("chroot to .git: %w", err)
	}
	subRepo, err := git.Open(
		filesystem.NewStorage(subGitDir, cache.NewObjectLRU(cache.DefaultMaxSize*10)),
		subFS,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("open submodule repository: %w", err)
	}
	subWorktree, err := subRepo.Worktree()
	if err != nil {
		return nil, nil, fmt.Errorf("get submodule worktree: %w", err)
	}
	return subRepo, subWorktree, nil
}

// cloneSubmodule clones a single submodule into the parent worktree.
// The caller is responsible for deciding whether to forward auth, so
// submoduleAuth may be nil even when the parent was authenticated.
func cloneSubmodule(ctx context.Context, logf func(string, ...any), parentWorktree *git.Worktree, subConfig *config.Submodule, expectedHash plumbing.Hash, resolvedURL string, submoduleAuth transport.AuthMethod, opts CloneRepoOptions) error {
	// Get the submodule directory within the parent worktree
	subFS, err := parentWorktree.Filesystem.Chroot(subConfig.Path)
	if err != nil {
		return fmt.Errorf("chroot to submodule path: %w", err)
	}

	// Check if already cloned
	if _, statErr := subFS.Stat(".git"); statErr == nil {
		logf("  Submodule already cloned, checking out expected commit...")
		subRepo, _, err := openSubmoduleRepo(parentWorktree, subConfig.Path)
		if err != nil {
			return fmt.Errorf("open existing submodule: %w", err)
		}
		return checkoutSubmoduleCommit(ctx, logf, subRepo, expectedHash, submoduleAuth, opts)
	}

	// Clone the submodule
	logf("  Cloning submodule from: %s", RedactURL(resolvedURL))

	// Create .git directory for the submodule
	if err := subFS.MkdirAll(".git", 0o755); err != nil {
		return fmt.Errorf("create .git directory: %w", err)
	}
	subGitDir, err := subFS.Chroot(".git")
	if err != nil {
		return fmt.Errorf("chroot to .git: %w", err)
	}
	gitStorage := filesystem.NewStorage(subGitDir, cache.NewObjectLRU(cache.DefaultMaxSize*10))

	// Clone the submodule repository. SingleBranch is false so all branches
	// are fetched and the expected commit is reachable. We honor the parent's
	// clone depth. If the expected commit is not reachable from the shallow
	// tip, the fetch-by-hash path in checkoutSubmoduleCommit will deepen as
	// needed.
	subRepo, err := git.CloneContext(ctx, gitStorage, subFS, &git.CloneOptions{
		URL:             resolvedURL,
		Auth:            submoduleAuth,
		Progress:        opts.Progress,
		InsecureSkipTLS: opts.Insecure,
		CABundle:        opts.CABundle,
		ProxyOptions:    opts.ProxyOptions,
		Depth:           opts.Depth,
		SingleBranch:    false,
		NoCheckout:      true,
	})
	if err != nil {
		_ = billyutil.RemoveAll(subFS, ".git")
		return fmt.Errorf("clone submodule repository: %w", err)
	}

	return checkoutSubmoduleCommit(ctx, logf, subRepo, expectedHash, submoduleAuth, opts)
}

// checkoutSubmoduleCommit ensures expectedHash is present in subRepo,
// fetching it from the remote if it is not already there, and then checks
// it out into the submodule's worktree.
func checkoutSubmoduleCommit(ctx context.Context, logf func(string, ...any), subRepo *git.Repository, expectedHash plumbing.Hash, submoduleAuth transport.AuthMethod, opts CloneRepoOptions) error {
	// Verify the commit exists
	logf("  Verifying commit exists: %s", expectedHash)
	if _, err := subRepo.CommitObject(expectedHash); err != nil {
		// Commit not found, try fetching with the specific hash
		logf("  Commit not found, attempting to fetch it directly...")
		fetchErr := subRepo.FetchContext(ctx, &git.FetchOptions{
			RemoteName: "origin",
			RefSpecs: []config.RefSpec{
				config.RefSpec("+" + expectedHash.String() + ":" + expectedHash.String()),
			},
			Auth:            submoduleAuth,
			Progress:        opts.Progress,
			InsecureSkipTLS: opts.Insecure,
			CABundle:        opts.CABundle,
			ProxyOptions:    opts.ProxyOptions,
		})
		if fetchErr != nil && !errors.Is(fetchErr, git.NoErrAlreadyUpToDate) {
			// If that fails, try fetching all refs
			logf("  Direct fetch failed (%v), fetching all refs...", fetchErr)
			fetchAllErr := subRepo.FetchContext(ctx, &git.FetchOptions{
				RemoteName:      "origin",
				Auth:            submoduleAuth,
				Progress:        opts.Progress,
				InsecureSkipTLS: opts.Insecure,
				CABundle:        opts.CABundle,
				ProxyOptions:    opts.ProxyOptions,
			})
			if fetchAllErr != nil && !errors.Is(fetchAllErr, git.NoErrAlreadyUpToDate) {
				return fmt.Errorf("fetch commit %s: %w", expectedHash, fetchAllErr)
			}
		}
		// Verify again
		if _, err := subRepo.CommitObject(expectedHash); err != nil {
			return fmt.Errorf("commit %s still not found after fetch: %w", expectedHash, err)
		}
	}

	// Checkout the specific commit expected by the parent repository
	logf("  Checking out commit: %s", expectedHash)
	subWorktree, err := subRepo.Worktree()
	if err != nil {
		return fmt.Errorf("get submodule worktree: %w", err)
	}
	if err := subWorktree.Checkout(&git.CheckoutOptions{Hash: expectedHash}); err != nil {
		return fmt.Errorf("checkout expected commit %s: %w", expectedHash, err)
	}
	return nil
}
