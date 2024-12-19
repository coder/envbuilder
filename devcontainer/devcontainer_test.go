package devcontainer_test

import (
	"crypto/md5"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coder/envbuilder/devcontainer"
	"github.com/coder/envbuilder/devcontainer/features"
	"github.com/coder/envbuilder/testutil/registrytest"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/require"
)

const workingDir = "/.envbuilder"

func stubLookupEnv(string) (string, bool) {
	return "", false
}

func TestParse(t *testing.T) {
	t.Parallel()
	raw := `{
  "build": {
    "dockerfile": "Dockerfile",
    "context": ".",
  },
  // Comments here!
  "image": "codercom/code-server:latest"
}`
	parsed, err := devcontainer.Parse([]byte(raw))
	require.NoError(t, err)
	require.Equal(t, "Dockerfile", parsed.Build.Dockerfile)
}

func TestCompileWithFeatures(t *testing.T) {
	t.Parallel()
	registry := registrytest.New(t)
	featureOne := registrytest.WriteContainer(t, registry, "coder/one:tomato", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:          "rust",
			Version:     "tomato",
			Name:        "Rust",
			Description: "Example description!",
			ContainerEnv: map[string]string{
				"TOMATO": "example",
			},
		},
	})
	featureTwo := registrytest.WriteContainer(t, registry, "coder/two:potato", features.TarLayerMediaType, map[string]any{
		"install.sh": "hey",
		"devcontainer-feature.json": features.Spec{
			ID:          "go",
			Version:     "potato",
			Name:        "Go",
			Description: "Example description!",
			ContainerEnv: map[string]string{
				"POTATO": "example",
			},
			Options: map[string]features.Option{
				"version": {
					Type: "string",
				},
			},
		},
	})

	raw := `{
  "build": {
    "dockerfile": "Dockerfile",
    "context": ".",
  },
  // Comments here!
  "image": "localhost:5000/envbuilder-test-codercom-code-server:latest",
  "features": {
	"` + featureOne + `": {},
	"` + featureTwo + `": "potato"
  }
}`
	dc, err := devcontainer.Parse([]byte(raw))
	require.NoError(t, err)
	fs := memfs.New()

	featureOneMD5 := md5.Sum([]byte(featureOne))
	featureOneDir := fmt.Sprintf("/.envbuilder/features/one-%x", featureOneMD5[:4])
	featureTwoMD5 := md5.Sum([]byte(featureTwo))
	featureTwoDir := fmt.Sprintf("/.envbuilder/features/two-%x", featureTwoMD5[:4])

	t.Run("WithoutBuildContexts", func(t *testing.T) {
		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)

		require.Equal(t, `FROM localhost:5000/envbuilder-test-codercom-code-server:latest

USER root
# Rust tomato - Example description!
WORKDIR `+featureOneDir+`
ENV TOMATO=example
RUN _CONTAINER_USER="1000" _REMOTE_USER="1000" ./install.sh
# Go potato - Example description!
WORKDIR `+featureTwoDir+`
ENV POTATO=example
RUN VERSION="potato" _CONTAINER_USER="1000" _REMOTE_USER="1000" ./install.sh
USER 1000`, params.DockerfileContent)
	})

	t.Run("WithBuildContexts", func(t *testing.T) {
		params, err := dc.Compile(fs, "", workingDir, "", "", true, stubLookupEnv)
		require.NoError(t, err)

		registryHost := strings.TrimPrefix(registry, "http://")

		require.Equal(t, `FROM scratch AS envbuilder_feature_one
COPY --from=`+registryHost+`/coder/one / /

FROM scratch AS envbuilder_feature_two
COPY --from=`+registryHost+`/coder/two / /

FROM localhost:5000/envbuilder-test-codercom-code-server:latest

USER root
# Rust tomato - Example description!
WORKDIR /.envbuilder/features/one
ENV TOMATO=example
RUN --mount=type=bind,from=envbuilder_feature_one,target=/.envbuilder/features/one,rw _CONTAINER_USER="1000" _REMOTE_USER="1000" ./install.sh
# Go potato - Example description!
WORKDIR /.envbuilder/features/two
ENV POTATO=example
RUN --mount=type=bind,from=envbuilder_feature_two,target=/.envbuilder/features/two,rw VERSION="potato" _CONTAINER_USER="1000" _REMOTE_USER="1000" ./install.sh
USER 1000`, params.DockerfileContent)

		require.Equal(t, map[string]string{
			registryHost + "/coder/one": featureOneDir,
			registryHost + "/coder/two": featureTwoDir,
		}, params.FeatureContexts)
	})
}

func TestCompileDevContainer(t *testing.T) {
	t.Parallel()
	t.Run("WithImage", func(t *testing.T) {
		t.Parallel()
		fs := memfs.New()
		dc := &devcontainer.Spec{
			Image: "localhost:5000/envbuilder-test-ubuntu:latest",
		}
		params, err := dc.Compile(fs, "", workingDir, "", "", false, stubLookupEnv)
		require.NoError(t, err)
		require.Equal(t, filepath.Join(workingDir, "Dockerfile"), params.DockerfilePath)
		require.Equal(t, workingDir, params.BuildContext)
	})
	t.Run("WithBuild", func(t *testing.T) {
		t.Parallel()
		fs := memfs.New()
		dc := &devcontainer.Spec{
			Build: devcontainer.BuildSpec{
				Dockerfile: "Dockerfile",
				Context:    ".",
				Args: map[string]string{
					"ARG1": "value1",
					"ARG2": "${localWorkspaceFolderBasename}",
				},
			},
		}
		dcDir := "/workspaces/coder/.devcontainer"
		err := fs.MkdirAll(dcDir, 0o755)
		require.NoError(t, err)
		file, err := fs.OpenFile(filepath.Join(dcDir, "Dockerfile"), os.O_CREATE|os.O_WRONLY, 0o644)
		require.NoError(t, err)
		_, err = io.WriteString(file, "FROM localhost:5000/envbuilder-test-ubuntu:latest")
		require.NoError(t, err)
		_ = file.Close()
		params, err := dc.Compile(fs, dcDir, workingDir, "", "/var/workspace", false, stubLookupEnv)
		require.NoError(t, err)
		require.Equal(t, "ARG1=value1", params.BuildArgs[0])
		require.Equal(t, "ARG2=workspace", params.BuildArgs[1])
		require.Equal(t, filepath.Join(dcDir, "Dockerfile"), params.DockerfilePath)
		require.Equal(t, dcDir, params.BuildContext)
	})
}

func TestImageFromDockerfile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		content string
		image   string
	}{{
		content: "FROM ubuntu",
		image:   "index.docker.io/library/ubuntu:latest",
	}, {
		content: "ARG VARIANT=bionic\nFROM ubuntu:$VARIANT",
		image:   "index.docker.io/library/ubuntu:bionic",
	}, {
		content: "ARG VARIANT=\"3.10\"\nFROM mcr.microsoft.com/devcontainers/python:0-${VARIANT}",
		image:   "mcr.microsoft.com/devcontainers/python:0-3.10",
	}, {
		content: "ARG VARIANT=\"3.10\"\nFROM mcr.microsoft.com/devcontainers/python:0-$VARIANT ",
		image:   "mcr.microsoft.com/devcontainers/python:0-3.10",
	}} {
		tc := tc
		t.Run(tc.image, func(t *testing.T) {
			t.Parallel()
			ref, err := devcontainer.ImageFromDockerfile(tc.content)
			require.NoError(t, err)
			require.Equal(t, tc.image, ref.Name())
		})
	}
}

func TestUserFrom(t *testing.T) {
	t.Parallel()

	t.Run("Image", func(t *testing.T) {
		t.Parallel()
		registry := registrytest.New(t)
		image, err := partial.UncompressedToImage(emptyImage{configFile: &v1.ConfigFile{
			Config: v1.Config{
				User: "example",
			},
		}})
		require.NoError(t, err)

		parsed, err := url.Parse("http://" + registry)
		require.NoError(t, err)
		parsed.Path = "coder/test:latest"
		ref, err := name.ParseReference(strings.TrimPrefix(parsed.String(), "http://"))
		require.NoError(t, err)
		err = remote.Write(ref, image)
		require.NoError(t, err)

		user, err := devcontainer.UserFromImage(ref)
		require.NoError(t, err)
		require.Equal(t, "example", user)
	})

	t.Run("Dockerfile", func(t *testing.T) {
		t.Parallel()
		tests := []struct {
			name    string
			content string
			user    string
		}{
			{
				name:    "Empty",
				content: "FROM scratch",
				user:    "",
			},
			{
				name:    "User",
				content: "FROM scratch\nUSER kyle",
				user:    "kyle",
			},
			{
				name:    "Env with default",
				content: "FROM scratch\nENV MYUSER=maf\nUSER ${MYUSER}",
				user:    "${MYUSER}", // This should be "maf" but the current implementation doesn't support this.
			},
			{
				name:    "Env var with default",
				content: "FROM scratch\nUSER ${MYUSER:-maf}",
				user:    "${MYUSER:-maf}", // This should be "maf" but the current implementation doesn't support this.
			},
			{
				name:    "Arg",
				content: "FROM scratch\nARG MYUSER\nUSER ${MYUSER}",
				user:    "${MYUSER}", // This should be "" or populated but the current implementation doesn't support this.
			},
			{
				name:    "Arg with default",
				content: "FROM scratch\nARG MYUSER=maf\nUSER ${MYUSER}",
				user:    "${MYUSER}", // This should be "maf" but the current implementation doesn't support this.
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				user, err := devcontainer.UserFromDockerfile(tt.content)
				require.NoError(t, err)
				require.Equal(t, tt.user, user)
			})
		}
	})

	t.Run("Multi-stage", func(t *testing.T) {
		t.Parallel()

		registry := registrytest.New(t)
		for tag, user := range map[string]string{
			"one": "maf",
			"two": "fam",
		} {
			image, err := partial.UncompressedToImage(emptyImage{configFile: &v1.ConfigFile{
				Config: v1.Config{
					User: user,
				},
			}})
			require.NoError(t, err)
			parsed, err := url.Parse("http://" + registry)
			require.NoError(t, err)
			parsed.Path = "coder/test:" + tag
			ref, err := name.ParseReference(strings.TrimPrefix(parsed.String(), "http://"))
			fmt.Println(ref)
			require.NoError(t, err)
			err = remote.Write(ref, image)
			require.NoError(t, err)
		}

		tests := []struct {
			name    string
			images  map[string]string
			content string
			user    string
		}{
			{
				name:    "Single",
				content: "FROM coder/test:one",
				user:    "maf",
			},
			{
				name:    "Multi",
				content: "FROM ubuntu AS u\nFROM coder/test:two",
				user:    "fam",
			},
			{
				name:    "Multi-2",
				content: "FROM coder/test:two AS two\nUSER maffam\nFROM coder/test:one AS one",
				user:    "maf",
			},
			{
				name:    "Multi-3",
				content: "FROM coder/test:two AS two\nFROM coder/test:one AS one\nUSER fammaf",
				user:    "fammaf",
			},
			{
				name: "Multi-4",
				content: `FROM ubuntu AS a
USER root
RUN useradd --create-home pickme
USER pickme
FROM a AS other
USER root
RUN useradd --create-home notme
USER notme
FROM a`,
				user: "pickme",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()

				content := strings.ReplaceAll(tt.content, "coder/test", strings.TrimPrefix(registry, "http://")+"/coder/test")

				user, err := devcontainer.UserFromDockerfile(content)
				require.NoError(t, err)
				require.Equal(t, tt.user, user)
			})
		}
	})
}

type emptyImage struct {
	configFile *v1.ConfigFile
}

func (i emptyImage) MediaType() (types.MediaType, error) {
	return types.DockerManifestSchema2, nil
}

func (i emptyImage) RawConfigFile() ([]byte, error) {
	return partial.RawConfigFile(i)
}

func (i emptyImage) ConfigFile() (*v1.ConfigFile, error) {
	return i.configFile, nil
}

func (i emptyImage) LayerByDiffID(h v1.Hash) (partial.UncompressedLayer, error) {
	return nil, fmt.Errorf("LayerByDiffID(%s): empty image", h)
}
