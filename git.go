package envbuilder

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/coder/coder/v2/codersdk"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/capability"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/filesystem"
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
	parsed, err := url.Parse(opts.RepoURL)
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

	err = opts.Storage.MkdirAll(opts.Path, 0755)
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
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, f); err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}
	k, err := gossh.ParsePrivateKey(buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse private key file: %w", err)
	}
	return k, nil
}

// KeyScan dials the server located at gitURL and fetches the SSH
// public keys returned in a format accepted by known_hosts.
// If no host keys found, returns an error.
func KeyScan(log LoggerFunc, gitURL *url.URL) ([]byte, error) {
	var buf bytes.Buffer
	conf := &gossh.ClientConfig{
		// Accept and record all host keys
		HostKeyCallback: func(dialAddr string, _ net.Addr, key gossh.PublicKey) error {
			kh, err := KnownHostsLine(dialAddr, key)
			if err != nil {
				return fmt.Errorf("ssh keyscan: generate known hosts line: %w", err)
			}
			log(codersdk.LogLevelInfo, "ssh keyscan: %s", kh)
			buf.WriteString(kh)
			buf.WriteString("\n")
			return nil
		},
	}
	dialAddr := hostPort(gitURL)
	client, err := gossh.Dial("tcp", dialAddr, conf)
	if err != nil {
		// The dial may fail due to no authentication methods, but this is fine.
		if netErr, ok := err.(net.Error); ok {
			return nil, fmt.Errorf("ssh keyscan: dial %s: %w", dialAddr, netErr)
		}
		// Otherwise, assume success.
	}
	defer func() {
		if client != nil {
			_ = client.Close()
		}
	}()

	bs := buf.Bytes()
	if len(bs) == 0 {
		return nil, fmt.Errorf("ssh keyscan: found no host keys")
	}
	return buf.Bytes(), nil
}

// KnownHostsLine generates a corresponding line for known_hosts
// given a dial address in the format host:port and a public key.
func KnownHostsLine(dialAddr string, key gossh.PublicKey) (string, error) {
	if !strings.Contains(dialAddr, ":") {
		return "", fmt.Errorf("invalid dialAddr, expected host:port")
	}
	h := strings.Split(dialAddr, ":")[0]
	k64 := base64.StdEncoding.EncodeToString(key.Marshal())
	return fmt.Sprintf("%s %s %s", h, key.Type(), k64), nil
}

func hostPort(u *url.URL) string {
	p := 22 // assume default SSH port
	if _p, err := strconv.Atoi(u.Port()); err == nil {
		p = _p
	}
	return fmt.Sprintf("%s:%d", u.Host, p)
}

var schemaRe = regexp.MustCompile(`^[a-zA-Z]+://`)

// ParseGitURL will normalize a git URL without a leading schema.
// If no schema is provided, we will default to ssh://.
func ParseGitURL(gitURL string) (*url.URL, error) {
	if !schemaRe.MatchString(gitURL) {
		gitURL = "ssh://" + gitURL

	}
	return url.Parse(gitURL)
}
