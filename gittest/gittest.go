package gittest

import (
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/format/pktline"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/server"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/stretchr/testify/require"
)

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

// NewRepo returns a new Git repository.
func NewRepo(t *testing.T, fs billy.Filesystem) *git.Repository {
	storage := filesystem.NewStorage(fs, cache.NewObjectLRU(cache.DefaultMaxSize))
	repo, err := git.Init(storage, fs)
	require.NoError(t, err)

	// This changes the default ref to main instead of master.
	h := plumbing.NewSymbolicReference(plumbing.HEAD, plumbing.ReferenceName("refs/heads/main"))
	err = storage.SetReference(h)
	require.NoError(t, err)

	return repo
}

// WriteFile writes a file to the filesystem.
func WriteFile(t *testing.T, fs billy.Filesystem, path, content string) {
	file, err := fs.OpenFile(path, os.O_CREATE|os.O_RDWR, 0644)
	require.NoError(t, err)
	_, err = file.Write([]byte(content))
	require.NoError(t, err)
	err = file.Close()
	require.NoError(t, err)
}

func BasicAuthMW(username, password string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if username != "" || password != "" {
				authUser, authPass, ok := r.BasicAuth()
				if !ok || username != authUser || password != authPass {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}
