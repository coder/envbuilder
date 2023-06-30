package registrytest

import (
	"archive/tar"
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

// New creates a new registry server that discards all logs.
func New(t *testing.T) string {
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return srv.URL
}

// WriteContainer uploads a container to the registry server.
// It returns the reference to the uploaded container.
func WriteContainer(t *testing.T, serverURL, containerRef, mediaType string, files map[string]any) string {
	var buf bytes.Buffer
	hasher := crypto.SHA256.New()
	mw := io.MultiWriter(&buf, hasher)
	wtr := tar.NewWriter(mw)
	for name, content := range files {
		var data []byte
		switch content := content.(type) {
		case string:
			data = []byte(content)
		case []byte:
			data = content
		default:
			var err error
			data, err = json.Marshal(content)
			require.NoError(t, err)
		}
		err := wtr.WriteHeader(&tar.Header{
			Mode:     0777,
			Name:     name,
			Typeflag: tar.TypeReg,
			Size:     int64(len(data)),
		})
		require.NoError(t, err)
		_, err = wtr.Write(data)
		require.NoError(t, err)
	}

	h := v1.Hash{
		Algorithm: "sha256",
		Hex:       hex.EncodeToString(hasher.Sum(make([]byte, 0, hasher.Size()))),
	}
	layer, err := partial.UncompressedToLayer(&uncompressedLayer{
		diffID:    h,
		mediaType: types.MediaType(mediaType),
		content:   buf.Bytes(),
	})
	require.NoError(t, err)

	image, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer: layer,
		History: v1.History{
			Author:    "registrytest",
			Created:   v1.Time{Time: time.Now()},
			Comment:   "created by the registrytest package",
			CreatedBy: "registrytest",
		},
	})
	require.NoError(t, err)

	parsed, err := url.Parse(serverURL)
	require.NoError(t, err)
	parsed.Path = containerRef

	ref, err := name.ParseReference(strings.TrimPrefix(parsed.String(), "http://"))
	require.NoError(t, err)

	err = remote.Write(ref, image)
	require.NoError(t, err)

	return ref.String()
}

// uncompressedLayer implements partial.UncompressedLayer from raw bytes.
type uncompressedLayer struct {
	diffID    v1.Hash
	mediaType types.MediaType
	content   []byte
}

// DiffID implements partial.UncompressedLayer
func (ul *uncompressedLayer) DiffID() (v1.Hash, error) {
	return ul.diffID, nil
}

// Uncompressed implements partial.UncompressedLayer
func (ul *uncompressedLayer) Uncompressed() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewBuffer(ul.content)), nil
}

// MediaType returns the media type of the layer
func (ul *uncompressedLayer) MediaType() (types.MediaType, error) {
	return ul.mediaType, nil
}
