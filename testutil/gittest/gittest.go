package gittest

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/coder/envbuilder/testutil/mwtest"
	"github.com/gliderlabs/ssh"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/server"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/stretchr/testify/require"
)

type Options struct {
	Files    map[string]string
	Username string
	Password string
	AuthMW   func(http.Handler) http.Handler
	TLS      bool
}

// CreateGitServer creates a git repository with an in-memory filesystem
// and serves it over HTTP using a httptest.Server.
func CreateGitServer(t *testing.T, opts Options) *httptest.Server {
	t.Helper()
	if opts.AuthMW == nil {
		opts.AuthMW = mwtest.BasicAuthMW(opts.Username, opts.Password)
	}
	commits := make([]CommitFunc, 0)
	for path, content := range opts.Files {
		commits = append(commits, Commit(t, path, content, "my test commit"))
	}
	fs := memfs.New()
	_ = NewRepo(t, fs, commits...)
	if opts.TLS {
		return httptest.NewTLSServer(opts.AuthMW(NewServer(fs)))
	}
	return httptest.NewServer(opts.AuthMW(NewServer(fs)))
}

// NewServer returns a http.Handler that serves a git repository.
// It's expected that the repository is already initialized by the caller.
func NewServer(fs billy.Filesystem) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/info/refs", func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("service") != "git-upload-pack" {
			http.Error(rw, "only smart git", 403)
			return
		}
		rw.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		ep, err := transport.NewEndpoint("/")
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		svr := server.NewServer(server.NewFilesystemLoader(fs))
		sess, err := svr.NewUploadPackSession(ep, nil)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		ar, err := sess.AdvertisedReferencesContext(r.Context())
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
		ar.Prefix = [][]byte{
			[]byte("# service=git-upload-pack"),
			pktline.Flush,
		}
		err = ar.Encode(rw)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}
	})
	mux.HandleFunc("/git-upload-pack", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("content-type", "application/x-git-upload-pack-result")

		upr := packp.NewUploadPackRequest()
		err := upr.Decode(r.Body)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			return
		}

		ep, err := transport.NewEndpoint("/")
		if err != nil {
			http.Error(rw, err.Error(), 500)
			log.Println(err)
			return
		}
		ld := server.NewFilesystemLoader(fs)
		svr := server.NewServer(ld)
		sess, err := svr.NewUploadPackSession(ep, nil)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			log.Println(err)
			return
		}
		res, err := sess.UploadPack(r.Context(), upr)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			log.Println(err)
			return
		}

		err = res.Encode(rw)
		if err != nil {
			http.Error(rw, err.Error(), 500)
			log.Println(err)
			return
		}
	})
	return mux
}

func NewServerSSH(t *testing.T, fs billy.Filesystem, pubkeys ...gossh.PublicKey) *transport.Endpoint {
	t.Helper()

	l, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })

	srvOpts := []ssh.Option{
		ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			for _, pk := range pubkeys {
				if ssh.KeysEqual(pk, key) {
					return true
				}
			}
			return false
		}),
	}

	done := make(chan struct{}, 1)
	go func() {
		_ = ssh.Serve(l, handleSession, srvOpts...)
		close(done)
	}()
	t.Cleanup(func() {
		_ = l.Close()
		<-done
	})

	addr, ok := l.Addr().(*net.TCPAddr)
	require.True(t, ok)
	tr, err := transport.NewEndpoint(fmt.Sprintf("ssh://git@%s:%d/", addr.IP, addr.Port))
	require.NoError(t, err)
	return tr
}

func handleSession(sess ssh.Session) {
	c := sess.Command()
	if len(c) < 1 {
		_, _ = fmt.Fprintf(os.Stderr, "invalid command: %q\n", c)
	}

	cmd := exec.Command(c[0], c[1:]...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cmd stdout pipe: %s\n", err.Error())
		return
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cmd stdin pipe: %s\n", err.Error())
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "cmd stderr pipe: %s\n", err.Error())
		return
	}

	err = cmd.Start()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "start cmd: %s\n", err.Error())
		return
	}

	go func() {
		defer stdin.Close()
		_, _ = io.Copy(stdin, sess)
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(sess.Stderr(), stderr)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(sess, stdout)
	}()

	wg.Wait()

	if err := cmd.Wait(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "wait cmd: %s\n", err.Error())
	}
}

// CommitFunc commits to a repo.
type CommitFunc func(billy.Filesystem, *git.Repository)

// Commit is a test helper for committing a single file to a repo.
func Commit(t *testing.T, path, content, msg string) CommitFunc {
	return func(fs billy.Filesystem, repo *git.Repository) {
		t.Helper()
		tree, err := repo.Worktree()
		require.NoError(t, err)
		WriteFile(t, fs, path, content)
		_, err = tree.Add(path)
		require.NoError(t, err)
		commit, err := tree.Commit(msg, &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Example",
				Email: "test@example.com",
				When:  time.Now(),
			},
		})
		require.NoError(t, err)
		_, err = repo.CommitObject(commit)
		require.NoError(t, err)
	}
}

// NewRepo returns a new Git repository.
func NewRepo(t *testing.T, fs billy.Filesystem, commits ...CommitFunc) *git.Repository {
	t.Helper()
	storage := filesystem.NewStorage(fs, cache.NewObjectLRU(cache.DefaultMaxSize))
	repo, err := git.Init(storage, fs)
	require.NoError(t, err)

	// This changes the default ref to main instead of master.
	h := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.ReferenceName("refs/heads/main"))
	err = storage.SetReference(h)
	require.NoError(t, err)

	for _, commit := range commits {
		commit(fs, repo)
	}
	return repo
}

// CreateGitServerWithSubmodule creates a parent git repo with a submodule pointing to another repo.
// Returns the parent server and the submodule server.
func CreateGitServerWithSubmodule(t *testing.T, opts Options, submoduleOpts Options) (parentSrv *httptest.Server, submoduleSrv *httptest.Server) {
	t.Helper()

	// Create the submodule repo first
	submoduleSrv = CreateGitServer(t, submoduleOpts)

	// Create the parent repo with .gitmodules pointing to submodule
	if opts.AuthMW == nil {
		opts.AuthMW = mwtest.BasicAuthMW(opts.Username, opts.Password)
	}

	fs := memfs.New()
	commits := make([]CommitFunc, 0)
	for path, content := range opts.Files {
		commits = append(commits, Commit(t, path, content, "my test commit"))
	}
	// Add gitmodules file pointing to the submodule server
	gitmodulesContent := fmt.Sprintf(`[submodule "submod"]
	path = submod
	url = %s
`, submoduleSrv.URL)
	commits = append(commits, Commit(t, ".gitmodules", gitmodulesContent, "add submodule"))
	_ = NewRepo(t, fs, commits...)

	if opts.TLS {
		parentSrv = httptest.NewTLSServer(opts.AuthMW(NewServer(fs)))
	} else {
		parentSrv = httptest.NewServer(opts.AuthMW(NewServer(fs)))
	}
	return parentSrv, submoduleSrv
}

// WriteFile writes a file to the filesystem.
func WriteFile(t *testing.T, fs billy.Filesystem, path, content string) {
	t.Helper()
	file, err := fs.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	require.NoError(t, err)
	_, err = file.Write([]byte(content))
	require.NoError(t, err)
	err = file.Close()
	require.NoError(t, err)
}
