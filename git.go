package envbuilder

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp/sideband"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

type CloneRepoOptions struct {
	Path    string
	Storage billy.Filesystem

	RepoURL  string
	RepoAuth transport.AuthMethod
	Progress sideband.Progress
	Insecure bool
}

// CloneRepo will clone the repository at the given URL into the given path.
// If a repository is already initialized at the given path, it will not
// be cloned again.
func CloneRepo(ctx context.Context, opts CloneRepoOptions) error {
	parsed, err := url.Parse(opts.RepoURL)
	if err != nil {
		return fmt.Errorf("parse url %q: %w", opts.RepoURL, err)
	}
	err = opts.Storage.MkdirAll(opts.Path, 0755)
	if err != nil {
		return fmt.Errorf("mkdir %q: %w", opts.Path, err)
	}
	reference := parsed.Fragment
	if reference == "" {
		reference = "refs/heads/main"
	}
	parsed.RawFragment = ""
	parsed.Fragment = ""
	fs, err := opts.Storage.Chroot(opts.Path)
	if err != nil {
		return fmt.Errorf("chroot %q: %w", opts.Path, err)
	}
	gitDir, err := fs.Chroot(".git")
	if err != nil {
		return fmt.Errorf("chroot .git: %w", err)
	}
	gitStorage := filesystem.NewStorage(gitDir, cache.NewObjectLRU(cache.DefaultMaxSize*10))
	fsStorage := filesystem.NewStorage(fs, cache.NewObjectLRU(cache.DefaultMaxSize*10))
	repo, err := git.Open(fsStorage, gitDir)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		err = nil
	}
	if err != nil {
		return fmt.Errorf("open %q: %w", opts.RepoURL, err)
	}
	if repo != nil {
		return nil
	}

	_, err = git.CloneContext(ctx, gitStorage, fs, &git.CloneOptions{
		URL:             parsed.String(),
		Auth:            opts.RepoAuth,
		Progress:        opts.Progress,
		ReferenceName:   plumbing.ReferenceName(reference),
		InsecureSkipTLS: opts.Insecure,
		Tags:            git.NoTags,
		SingleBranch:    true,
		Depth:           1,
	})
	if errors.Is(err, git.ErrRepositoryAlreadyExists) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("clone %q: %w", opts.RepoURL, err)
	}
	return nil
}
